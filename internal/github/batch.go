package github

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gh "github.com/google/go-github/v60/github"
	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/north-echo/fluxgate/internal/store"
)

// BatchOptions configures a batch scan.
type BatchOptions struct {
	Top         int
	List        string // path to file with owner/repo per line
	Resume      bool
	Delay       time.Duration // delay between repos when rate budget is low (0 = no delay)
	Concurrency int           // concurrent repo scans (<= 0 means 1)
	DB          *store.DB
	Opts        scanner.ScanOptions
}

// rateReserve is the remaining-quota floor below which workers honor the
// configured --delay. Above it, sleeping only wastes wall-clock time.
const rateReserve = 500

// RepoInfo holds basic repo metadata from GitHub search.
type RepoInfo struct {
	Owner    string
	Name     string
	Stars    int
	Language string
}

// FetchTopRepos returns the top N repos by star count from GitHub search API.
// GitHub limits search results to 1,000 per query, so for N > 1000 we use
// sliding star-count windows to paginate beyond the limit.
func (c *Client) FetchTopRepos(ctx context.Context, top int) ([]RepoInfo, error) {
	var repos []RepoInfo
	seen := make(map[string]bool)
	perPage := 100
	if top < perPage {
		perPage = top
	}

	// Start with a broad query; narrow the star range when we hit the 1000-result ceiling
	maxStars := 0 // 0 means no upper bound
	minStars := 1000

	for len(repos) < top {
		query := fmt.Sprintf("stars:%d..%d", minStars, maxStars)
		if maxStars == 0 {
			query = fmt.Sprintf("stars:>%d", minStars)
		}

		windowRepos, lowestStars, err := c.fetchSearchWindow(ctx, query, perPage, top-len(repos), seen)
		if err != nil {
			return repos, err
		}

		repos = append(repos, windowRepos...)
		fmt.Printf("  %d repos collected so far (stars >= %d)\n", len(repos), lowestStars)

		if len(windowRepos) == 0 || lowestStars <= minStars {
			break
		}

		// Slide the window: next query gets repos with fewer stars
		maxStars = lowestStars
	}

	if len(repos) > top {
		repos = repos[:top]
	}
	return repos, nil
}

// fetchSearchWindow fetches up to `limit` repos matching a star query, returning
// the repos found, the lowest star count seen, and any error.
func (c *Client) fetchSearchWindow(ctx context.Context, query string, perPage, limit int, seen map[string]bool) ([]RepoInfo, int, error) {
	var repos []RepoInfo
	lowestStars := math.MaxInt

	for page := 1; len(repos) < limit && page <= 10; page++ {
		searchOpts := &gh.SearchOptions{
			Sort:  "stars",
			Order: "desc",
			ListOptions: gh.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		}

		result, err := withRetryRotate(ctx, c, func() retryableFunc[*gh.RepositoriesSearchResult] {
			return func(ctx context.Context) (*gh.RepositoriesSearchResult, *gh.Response, error) {
				result, resp, err := c.current().Search.Repositories(ctx, query, searchOpts)
				return result, resp, err
			}
		})
		if err != nil {
			return repos, lowestStars, fmt.Errorf("searching repos (query=%s page=%d): %w", query, page, err)
		}

		for _, r := range result.Repositories {
			key := r.GetOwner().GetLogin() + "/" + r.GetName()
			if seen[key] {
				continue
			}
			seen[key] = true

			stars := r.GetStargazersCount()
			if stars < lowestStars {
				lowestStars = stars
			}

			repos = append(repos, RepoInfo{
				Owner:    r.GetOwner().GetLogin(),
				Name:     r.GetName(),
				Stars:    stars,
				Language: r.GetLanguage(),
			})
			if len(repos) >= limit {
				break
			}
		}

		if len(result.Repositories) < perPage {
			break
		}
	}

	return repos, lowestStars, nil
}

// LoadRepoList reads repos from a file (one owner/repo per line).
func LoadRepoList(path string) ([]RepoInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var repos []RepoInfo
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "/", 2)
		if len(parts) != 2 {
			continue
		}
		repos = append(repos, RepoInfo{Owner: parts[0], Name: parts[1]})
	}
	return repos, s.Err()
}

// BatchScan scans a list of repos and stores results in the database.
// Repos are fanned out to opts.Concurrency workers; scanning is network-bound
// (2+ API round trips per repo), so a serial loop leaves the wall clock almost
// entirely idle. Database writes are already serialized by the store's
// single-connection pool.
func (c *Client) BatchScan(ctx context.Context, repos []RepoInfo, opts BatchOptions) error {
	total := len(repos)
	if total == 0 {
		fmt.Println("No repos to scan.")
		return nil
	}
	workers := opts.Concurrency
	if workers <= 0 {
		workers = 1
	}
	if workers > total {
		workers = total
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var scanned, skipped, processed atomic.Int64
	var errOnce sync.Once
	var firstErr error
	fail := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}

	jobs := make(chan RepoInfo)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for repo := range jobs {
				if ctx.Err() != nil {
					return
				}
				c.scanOne(ctx, repo, opts, total, &scanned, &skipped, &processed, fail)
			}
		}()
	}

feed:
	for _, repo := range repos {
		select {
		case <-ctx.Done():
			break feed
		case jobs <- repo:
		}
	}
	close(jobs)
	wg.Wait()

	if firstErr != nil {
		return firstErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	fmt.Printf("\nBatch complete: %d scanned, %d skipped (already scanned)\n", scanned.Load(), skipped.Load())
	return nil
}

// scanOne processes a single repo within a BatchScan worker.
func (c *Client) scanOne(ctx context.Context, repo RepoInfo, opts BatchOptions, total int, scanned, skipped, processed *atomic.Int64, fail func(error)) {
	// Check for resume
	if opts.Resume {
		already, err := opts.DB.IsRepoScanned(repo.Owner, repo.Name)
		if err != nil {
			fail(fmt.Errorf("checking if %s/%s is scanned: %w", repo.Owner, repo.Name, err))
			return
		}
		if already {
			skipped.Add(1)
			processed.Add(1)
			return
		}
	}

	// Check no-workflow cache (skip API call for repos known to have no workflows)
	if opts.DB.HasNoWorkflows(repo.Owner, repo.Name, 7) {
		skipped.Add(1)
		processed.Add(1)
		return
	}

	n := processed.Add(1)
	header := fmt.Sprintf("[%d/%d] Scanning %s/%s", n, total, repo.Owner, repo.Name)
	if repo.Stars > 0 {
		header += fmt.Sprintf(" (%d stars)", repo.Stars)
	}
	fmt.Println(header)

	result, err := c.ScanRemote(ctx, repo.Owner, repo.Name, opts.Opts)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		fmt.Printf("  %s/%s error: %v\n", repo.Owner, repo.Name, err)
		// Cache repos with no workflows directory (404 errors)
		if strings.Contains(err.Error(), "404 Not Found") {
			opts.DB.MarkNoWorkflows(repo.Owner, repo.Name)
		}
		// Store the repo as scanned but with 0 findings so we don't retry
		emptyResult := &scanner.ScanResult{Path: fmt.Sprintf("%s/%s", repo.Owner, repo.Name)}
		if saveErr := opts.DB.SaveResult(repo.Owner, repo.Name, repo.Stars, repo.Language, emptyResult); saveErr != nil {
			fmt.Fprintf(os.Stderr, "  Warning: could not save error state: %v\n", saveErr)
		}
		return
	}

	if err := opts.DB.SaveResult(repo.Owner, repo.Name, repo.Stars, repo.Language, result); err != nil {
		fail(fmt.Errorf("saving results for %s/%s: %w", repo.Owner, repo.Name, err))
		return
	}

	scanned.Add(1)
	if len(result.Findings) > 0 {
		fmt.Printf("  %s/%s: %d issues in %d workflows\n", repo.Owner, repo.Name, len(result.Findings), result.Workflows)
	}

	// Honor --delay only when the observed rate budget is actually low;
	// sleeping with thousands of requests remaining wastes wall-clock time.
	if opts.Delay > 0 {
		if rem := c.rateRemaining(); rem >= 0 && rem < rateReserve {
			select {
			case <-ctx.Done():
			case <-time.After(opts.Delay):
			}
		}
	}
}
