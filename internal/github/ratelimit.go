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
	maxRetries     = 5
	baseBackoff    = 1 * time.Second
	maxBackoff     = 60 * time.Second
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
