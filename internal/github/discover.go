package github

import (
	"context"
	"fmt"
	"os"
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
				result, resp, err := c.gh.Search.Code(ctx, query, searchOpts)
				return result, resp, err
			}
		})
		if err != nil {
			return repos, fmt.Errorf("code search (page %d): %w", page, err)
		}

		for _, cr := range result.CodeResults {
			repo := cr.GetRepository()
			owner := repo.GetOwner().GetLogin()
			name := repo.GetName()
			key := fmt.Sprintf("%s/%s", owner, name)
			if seen[key] {
				continue
			}
			seen[key] = true

			stars := repo.GetStargazersCount()
			language := repo.GetLanguage()

			// Code search results often have zero/stale star counts.
			// If filtering by stars, fetch accurate repo info.
			if opts.MinStars > 0 {
				fullRepo, err := withRetryRotate(ctx, c, func() retryableFunc[*gh.Repository] {
					return func(ctx context.Context) (*gh.Repository, *gh.Response, error) {
						r, resp, err := c.gh.Repositories.Get(ctx, owner, name)
						return r, resp, err
					}
				})
				if err != nil {
					fmt.Fprintf(os.Stderr, "  Warning: could not fetch repo info for %s: %v\n", key, err)
					continue
				}
				stars = fullRepo.GetStargazersCount()
				language = fullRepo.GetLanguage()
				if stars < opts.MinStars {
					continue
				}
			}

			repos = append(repos, RepoInfo{
				Owner:    owner,
				Name:     name,
				Stars:    stars,
				Language: language,
			})
		}

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
