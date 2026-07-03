package github

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	gh "github.com/google/go-github/v60/github"
)

// DiscoverOptions configures a code-search-based discovery scan.
type DiscoverOptions struct {
	Trigger  string        // e.g. "pull_request_target"
	MinStars int           // minimum star count filter
	MaxPages int           // max search result pages (default 10, max 100 pages × 100 results = 10k)
	Delay    time.Duration // delay between API calls
}

// DiscoverRepos uses GitHub code search to find repos with specific workflow patterns.
// Note: GitHub code search does not support the stars: qualifier, so MinStars
// filtering is applied client-side. The star count in code search results may be
// zero/stale, so when MinStars is set we fetch accurate counts via the repos API.
func (c *Client) DiscoverRepos(ctx context.Context, opts DiscoverOptions) ([]RepoInfo, error) {
	query := fmt.Sprintf("path:.github/workflows %s language:YAML", opts.Trigger)

	seen := make(map[string]bool)
	var repos []RepoInfo

	maxPages := opts.MaxPages
	if maxPages == 0 {
		maxPages = 10
	}

	for page := 1; page <= maxPages; page++ {
		select {
		case <-ctx.Done():
			return repos, ctx.Err()
		default:
		}

		searchOpts := &gh.SearchOptions{
			Sort:  "indexed",
			Order: "desc",
			ListOptions: gh.ListOptions{
				Page:    page,
				PerPage: 100,
			},
		}

		result, err := withRetryRotate(ctx, c, func() retryableFunc[*gh.CodeSearchResult] {
			return func(ctx context.Context) (*gh.CodeSearchResult, *gh.Response, error) {
				result, resp, err := c.current().Search.Code(ctx, query, searchOpts)
				return result, resp, err
			}
		})
		if err != nil {
			return repos, fmt.Errorf("code search (page %d): %w", page, err)
		}

		var candidates []RepoInfo
		for _, cr := range result.CodeResults {
			repo := cr.GetRepository()
			owner := repo.GetOwner().GetLogin()
			name := repo.GetName()
			key := fmt.Sprintf("%s/%s", owner, name)
			if seen[key] {
				continue
			}
			seen[key] = true

			candidates = append(candidates, RepoInfo{
				Owner:    owner,
				Name:     name,
				Stars:    repo.GetStargazersCount(),
				Language: repo.GetLanguage(),
			})
		}

		// Code search results often have zero/stale star counts. If
		// filtering by stars, fetch accurate repo info — concurrently:
		// up to 100 serial Gets per page dominated discovery time.
		if opts.MinStars > 0 {
			candidates = c.fetchAccurateStars(ctx, candidates, opts.MinStars)
		}
		repos = append(repos, candidates...)

		fmt.Printf("  Code search page %d: %d results, %d unique repos so far\n",
			page, len(result.CodeResults), len(repos))

		if len(result.CodeResults) < 100 {
			break // no more results
		}

		// Code search has a stricter rate limit (10 req/min for authenticated)
		if opts.Delay > 0 && page < maxPages {
			select {
			case <-ctx.Done():
				return repos, ctx.Err()
			case <-time.After(opts.Delay):
			}
		}
	}

	return repos, nil
}

// fetchAccurateStars re-fetches star counts for candidates via the repos API
// (code-search star counts are often zero/stale) and drops repos below
// minStars. Fetches run through a small worker pool.
func (c *Client) fetchAccurateStars(ctx context.Context, candidates []RepoInfo, minStars int) []RepoInfo {
	const workers = 8

	keep := make([]bool, len(candidates))
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	for i := range candidates {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if ctx.Err() != nil {
				return
			}
			cand := &candidates[idx]
			fullRepo, err := withRetryRotate(ctx, c, func() retryableFunc[*gh.Repository] {
				return func(ctx context.Context) (*gh.Repository, *gh.Response, error) {
					r, resp, err := c.current().Repositories.Get(ctx, cand.Owner, cand.Name)
					return r, resp, err
				}
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "  Warning: could not fetch repo info for %s/%s: %v\n", cand.Owner, cand.Name, err)
				return
			}
			cand.Stars = fullRepo.GetStargazersCount()
			cand.Language = fullRepo.GetLanguage()
			keep[idx] = cand.Stars >= minStars
		}(i)
	}
	wg.Wait()

	var out []RepoInfo
	for i, k := range keep {
		if k {
			out = append(out, candidates[i])
		}
	}
	return out
}
