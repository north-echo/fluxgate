package github

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"time"

	gh "github.com/google/go-github/v60/github"
)

const (
	maxRetries  = 5
	baseBackoff = 1 * time.Second
	maxBackoff  = 60 * time.Second
)

// isRateLimited checks if an error is a GitHub rate limit error.
func isRateLimited(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := err.(*gh.RateLimitError); ok {
		return true
	}
	if _, ok := err.(*gh.AbuseRateLimitError); ok {
		return true
	}
	return false
}

// isRetryable checks if an error or response indicates a retryable condition.
func isRetryable(resp *gh.Response, err error) bool {
	if isRateLimited(err) {
		return true
	}
	if resp != nil && (resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == http.StatusServiceUnavailable ||
		resp.StatusCode == http.StatusBadGateway) {
		return true
	}
	return false
}

// backoffDuration calculates the wait time for a given retry attempt.
// If the response includes a Retry-After or rate limit reset, use that.
func backoffDuration(resp *gh.Response, attempt int) time.Duration {
	if resp != nil && resp.Rate.Reset.After(time.Now()) {
		wait := time.Until(resp.Rate.Reset.Time)
		if wait > 0 && wait < maxBackoff {
			return wait + time.Second // add 1s buffer
		}
	}

	d := time.Duration(math.Pow(2, float64(attempt))) * baseBackoff
	if d > maxBackoff {
		d = maxBackoff
	}
	return d
}

// retryableFunc is a function that can be retried on rate limit errors.
type retryableFunc[T any] func(ctx context.Context) (T, *gh.Response, error)

// withRetry wraps a GitHub API call with exponential backoff retry logic.
func withRetry[T any](ctx context.Context, fn retryableFunc[T]) (T, error) {
	var zero T
	for attempt := 0; attempt <= maxRetries; attempt++ {
		result, resp, err := fn(ctx)
		if err == nil {
			return result, nil
		}
		if !isRetryable(resp, err) || attempt == maxRetries {
			return zero, err
		}

		wait := backoffDuration(resp, attempt)
		fmt.Printf("  Rate limited, waiting %s (attempt %d/%d)...\n", wait.Round(time.Second), attempt+1, maxRetries)

		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(wait):
		}
	}
	return zero, fmt.Errorf("exceeded maximum retries")
}

// withRetryRotate wraps a GitHub API call with retry logic that also
// rotates tokens when rate limited. The fnFactory is called each attempt
// so it can use the current (possibly rotated) client.
func withRetryRotate[T any](ctx context.Context, c *Client, fnFactory func() retryableFunc[T]) (T, error) {
	var zero T
	rotations := 0
	for attempt := 0; attempt <= maxRetries; {
		fn := fnFactory()
		result, resp, err := fn(ctx)
		c.noteRate(resp)
		if err == nil {
			return result, nil
		}
		if !isRetryable(resp, err) {
			return zero, err
		}

		// Rotating to a fresh token does not consume a retry attempt.
		// With more tokens than maxRetries, counting rotations against the
		// budget could exhaust it without a single backoff wait.
		if isRateLimited(err) && rotations < c.tokenCount()-1 && c.rotateToken() {
			rotations++
			fmt.Printf("  Rate limited, rotating to next token (%d/%d)...\n", rotations+1, c.tokenCount())
			continue // retry immediately with new token
		}
		rotations = 0 // all tokens tried; back off, then rotate again

		// Quota truly exhausted with a distant reset: exponential backoff
		// capped at 60s cannot outlast it — it would just burn ~5 minutes
		// per call and fail anyway. Surface a clear error instead.
		if isRateLimited(err) && resp != nil && time.Until(resp.Rate.Reset.Time) > maxBackoff {
			return zero, fmt.Errorf("rate limit exhausted on all tokens, resets at %s: %w",
				resp.Rate.Reset.Time.Local().Format("15:04:05"), err)
		}

		if attempt == maxRetries {
			return zero, err
		}

		wait := backoffDuration(resp, attempt)
		fmt.Printf("  Rate limited, waiting %s (attempt %d/%d)...\n", wait.Round(time.Second), attempt+1, maxRetries)

		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-time.After(wait):
		}
		attempt++
	}
	return zero, fmt.Errorf("exceeded maximum retries")
}
