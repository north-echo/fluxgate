package github

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	gh "github.com/google/go-github/v60/github"
	"github.com/north-echo/fluxgate/internal/scanner"
	"github.com/north-echo/fluxgate/internal/store"
)

// BatchOptions configures a batch scan.
type BatchOptions struct {
	Top    int
	List   string // path to file with owner/repo per line
	Resume bool
	Delay  time.Duration // delay between repos (0 = no delay)
	DB     *store.DB
	Opts   scanner.ScanOptions
}

// RepoInfo holds basic repo metadata from GitHub search.
type RepoInfo struct {
	Owner    string
	Name     string
	Stars    int
	Language string
}

// FetchTopRepos returns the top N repos by star count from GitHub search API.
func (c *Client) FetchTopRepos(ctx context.Context, top int) ([]RepoInfo, error) {
	var repos []RepoInfo
	perPage := 100
	if top < perPage {
		perPage = top
	}

	for page := 1; len(repos) < top; page++ {
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
				result, resp, err := c.gh.Search.Repositories(ctx, "stars:>1000", searchOpts)
				return result, resp, err
			}
		})
		if err != nil {
			return repos, fmt.Errorf("searching repos (page %d): %w", page, err)
		}

		for _, r := range result.Repositories {
			repos = append(repos, RepoInfo{
				Owner:    r.GetOwner().GetLogin(),
				Name:     r.GetName(),
				Stars:    r.GetStargazersCount(),
				Language: r.GetLanguage(),
			})
			if len(repos) >= top {
				break
			}
		}

		if len(result.Repositories) < perPage {
			break // no more results
		}
	}

	return repos, nil
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
func (c *Client) BatchScan(ctx context.Context, repos []RepoInfo, opts BatchOptions) error {
	total := len(repos)
	scanned := 0
	skipped := 0

	for i, repo := range repos {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check for resume
		if opts.Resume {
			already, err := opts.DB.IsRepoScanned(repo.Owner, repo.Name)
			if err != nil {
				return fmt.Errorf("checking if %s/%s is scanned: %w", repo.Owner, repo.Name, err)
			}
			if already {
				skipped++
				continue
			}
		}

		// Check no-workflow cache (skip API call for repos known to have no workflows)
		if opts.DB.HasNoWorkflows(repo.Owner, repo.Name, 7) {
			skipped++
			continue
		}

		fmt.Printf("[%d/%d] Scanning %s/%s", i+1, total, repo.Owner, repo.Name)
		if repo.Stars > 0 {
			fmt.Printf(" (%d stars)", repo.Stars)
		}
		fmt.Println()

		result, err := c.ScanRemote(ctx, repo.Owner, repo.Name, opts.Opts)
		if err != nil {
			fmt.Printf("  Error: %v\n", err)
			// Cache repos with no workflows directory (404 errors)
			if strings.Contains(err.Error(), "404 Not Found") {
				opts.DB.MarkNoWorkflows(repo.Owner, repo.Name)
			}
			// Store the repo as scanned but with 0 findings so we don't retry
			emptyResult := &scanner.ScanResult{Path: fmt.Sprintf("%s/%s", repo.Owner, repo.Name)}
			if saveErr := opts.DB.SaveResult(repo.Owner, repo.Name, repo.Stars, repo.Language, emptyResult); saveErr != nil {
				fmt.Fprintf(os.Stderr, "  Warning: could not save error state: %v\n", saveErr)
			}
			continue
		}

		if err := opts.DB.SaveResult(repo.Owner, repo.Name, repo.Stars, repo.Language, result); err != nil {
			return fmt.Errorf("saving results for %s/%s: %w", repo.Owner, repo.Name, err)
		}

		scanned++
		if len(result.Findings) > 0 {
			fmt.Printf("  Found %d issues in %d workflows\n", len(result.Findings), result.Workflows)
		}

		if opts.Delay > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(opts.Delay):
			}
		}
	}

	fmt.Printf("\nBatch complete: %d scanned, %d skipped (already scanned)\n", scanned, skipped)
	return nil
}
