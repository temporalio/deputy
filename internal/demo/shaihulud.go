package demo

import (
	"cmp"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"sort"
	"strings"
	"sync"

	git "github.com/go-git/go-git/v5"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v63/github"
	"github.com/google/osv-scalibr/extractor"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-retryablehttp"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/repository"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
)

// WizShaiHuludIOCURL is the canonical CSV published by Wiz for the Shai-Hulud 2.0 campaign.
// The CSV is structured as "Package,Version" where Version can contain multiple exact
// versions separated by "||" and optionally prefixed with "=".
const WizShaiHuludIOCURL = "https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"

// Options configure the Shai-Hulud supply-chain scan demo.
type Options struct {
	// Owner is the GitHub organization or username to inspect.
	Owner string

	// Repos optionally restricts scanning to the provided repositories. When empty, all
	// repositories for Owner are enumerated via the GitHub API.
	Repos []string

	// GitHubClient can be supplied to override the default client (useful for tests or
	// GitHub Enterprise). When nil, a client is constructed using GITHUB_TOKEN if set.
	GitHubClient *github.Client

	// HTTPClient overrides the HTTP client used to download the IOC CSV. Defaults to
	// http.DefaultClient.
	HTTPClient *http.Client

	// IOCURL overrides the Wiz IOC CSV location. Defaults to WizShaiHuludIOCURL.
	IOCURL string

	// Concurrency limits the number of concurrent clone+scan operations. Defaults to 4.
	Concurrency int

	// CloneInMemory uses an in-memory workspace for clones when true (default: false).
	CloneInMemory bool

	// Ecosystems filters inventory scanning. Defaults to all supported ecosystems.
	Ecosystems []string
}

// ScanResult captures the outcome for a single repository.
type ScanResult struct {
	Owner           string
	Name            string
	CloneURL        string
	DependencyCount int
	Matches         []PackageMatch
	Error           error
}

// PackageMatch records a dependency that matched a Wiz IOC.
type PackageMatch struct {
	Package   string
	Version   string
	Ecosystem string
	PURL      string
	Locations []string
}

// ScanShaiHulud inventories dependencies for the provided GitHub owner and flags packages
// that match Wiz's Shai-Hulud IOCs. Errors while cloning or scanning a repository are captured
// in the corresponding RepoFinding so other repositories can continue.
func ScanShaiHulud(ctx context.Context, opts Options) ([]ScanResult, error) {
	if strings.TrimSpace(opts.Owner) == "" {
		return nil, fmt.Errorf("owner is required")
	}

	var (
		conc       = cmp.Or(opts.Concurrency, 4)
		iocURL     = cmp.Or(opts.IOCURL, WizShaiHuludIOCURL)
		httpClient = cmp.Or(opts.HTTPClient, http.DefaultClient)
	)

	iocs, err := fetchIOCSet(ctx, httpClient, iocURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Wiz IOCs: %w", err)
	}

	ghToken := os.Getenv("GITHUB_TOKEN")
	ghClient := cmp.Or(opts.GitHubClient, newGitHubClient(ctx, ghToken))
	if ghClient == nil {
		return nil, fmt.Errorf("failed to construct GitHub client")
	}

	repos, err := listRepos(ctx, ghClient, opts.Owner, opts.Repos)
	if err != nil {
		return nil, err
	}
	if len(repos) == 0 {
		return nil, fmt.Errorf("no repositories found for %q", opts.Owner)
	}

	var (
		mu       sync.Mutex
		findings []ScanResult
	)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(conc)
	for _, repo := range repos {
		g.Go(func() error {
			finding := scanRepo(ctx, repo, ghToken, opts.CloneInMemory, opts.Ecosystems, iocs)
			mu.Lock()
			findings = append(findings, finding)
			mu.Unlock()
			return nil
		})
	}

	_ = g.Wait()

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Owner == findings[j].Owner {
			return findings[i].Name < findings[j].Name
		}
		return findings[i].Owner < findings[j].Owner
	})

	return findings, nil
}

// repoTarget represents a GitHub repository to be scanned.
type repoTarget struct {
	owner    string
	name     string
	cloneURL string
}

// scanRepo clones and scans the given repository target, returning a ScanResult.
func scanRepo(ctx context.Context, target repoTarget, token string, inMemory bool, ecosystems []string, iocs iocSet) ScanResult {
	finding := ScanResult{Owner: target.owner, Name: target.name, CloneURL: target.cloneURL}
	if target.cloneURL == "" {
		finding.Error = fmt.Errorf("missing clone URL")
		return finding
	}

	cloneOpts := &git.CloneOptions{
		URL:          target.cloneURL,
		Depth:        1,
		SingleBranch: true,
		Tags:         git.NoTags,
		Auth:         githubAuth(token, target.cloneURL),
	}

	src, err := repository.Clone(ctx, cloneOpts, inMemory)
	if err != nil {
		finding.Error = fmt.Errorf("clone %s: %w", target.name, err)
		return finding
	}
	defer src.Close()

	pkgs, err := inv.ScanPackagesWorking(ctx, src.Workspace, inv.ScanOptions{Ecosystems: ecosystems})
	if err != nil {
		finding.Error = fmt.Errorf("inventory %s: %w", target.name, err)
		return finding
	}
	finding.DependencyCount = len(pkgs)
	// for _, p := range pkgs {
	// 	fmt.Println(p.Ecosystem(), p.Name, p.Version)
	// }
	finding.Matches = matchPackages(pkgs, iocs)
	return finding
}

// githubAuth constructs GitHub authentication for go-git using the provided token and URL.
func githubAuth(token, rawURL string) *githttp.BasicAuth {
	if token == "" {
		return nil
	}
	u, err := neturl.Parse(rawURL)
	if err == nil && u.Scheme != "" {
		host := strings.ToLower(u.Host)
		if host != "github.com" && !strings.HasSuffix(host, ".github.com") {
			return nil
		}
	}
	return &githttp.BasicAuth{Username: "oauth2", Password: token}
}

// iocSet represents a set of package names and versions used for IOC matching.
type iocSet struct {
	packages map[string]map[string]struct{}
}

// match reports whether the provided package name and version exist in the iocSet.
func (s iocSet) match(name, version string) bool {
	if len(s.packages) == 0 {
		return false
	}
	pkg := normalizeName(name)
	if pkg == "" {
		return false
	}
	versions, ok := s.packages[pkg]
	if !ok {
		return false
	}
	v := normalizeVersion(version)
	if v == "" {
		return false
	}
	if _, ok := versions[v]; ok {
		return true
	}
	return false
}

// add inserts the provided package and versions into the iocSet.
func (s *iocSet) add(pkg string, versions ...string) {
	if s.packages == nil {
		s.packages = make(map[string]map[string]struct{})
	}
	pkg = normalizeName(pkg)
	if pkg == "" {
		return
	}
	dest, ok := s.packages[pkg]
	if !ok {
		dest = make(map[string]struct{})
		s.packages[pkg] = dest
	}
	for _, v := range versions {
		v = normalizeVersion(v)
		if v == "" {
			continue
		}
		dest[v] = struct{}{}
	}
}

// fetchIOCSet downloads and parses the IOC CSV from the provided URL, returning an iocSet,
// or an error if the fetch or parse fails.
func fetchIOCSet(ctx context.Context, client *http.Client, url string) (iocSet, error) {
	if client == nil {
		return iocSet{}, fmt.Errorf("http client is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return iocSet{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return iocSet{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return iocSet{}, fmt.Errorf("fetch IOC csv: status %s", resp.Status)
	}

	reader := csv.NewReader(resp.Body)
	reader.FieldsPerRecord = -1
	var set iocSet
	first := true
	for {
		rec, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return iocSet{}, fmt.Errorf("parse CSV: %w", err)
		}
		if len(rec) < 2 {
			continue
		}
		pkg := strings.TrimSpace(rec[0])
		vers := strings.TrimSpace(rec[1])
		if first && strings.EqualFold(pkg, "package") {
			first = false
			continue
		}
		first = false
		versions := parseVersionList(vers)
		set.add(pkg, versions...)
	}
	return set, nil
}

// parseVersionList parses a version string containing one or more versions
// separated by "||", normalizing each version, and returns the list of unique versions.
func parseVersionList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, "||")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		v := normalizeVersion(p)
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// normalizeVersion trims and normalizes a version string for matching,
// removing any leading "=" and "v" or "V" prefixes (e.g., "= v1.2.3" -> "1.2.3").
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if after, ok := strings.CutPrefix(v, "="); ok {
		v = strings.TrimSpace(after)
	}
	if strings.HasPrefix(strings.ToLower(v), "v") {
		v = strings.TrimPrefix(v, "v")
		v = strings.TrimPrefix(v, "V")
	}
	return v
}

// normalizeName trims and lowercases a package name for matching, e.g., " React " -> "react".
func normalizeName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// matchPackages returns the subset of pkgs that match entries in the iocSet.
func matchPackages(pkgs []*extractor.Package, iocs iocSet) []PackageMatch {
	if len(pkgs) == 0 || len(iocs.packages) == 0 {
		return nil
	}
	matches := make([]PackageMatch, 0)
	for _, p := range pkgs {
		if p == nil {
			continue
		}
		if !iocs.match(p.Name, p.Version) {
			continue
		}
		var purl string
		if pu := p.PURL(); pu != nil {
			purl = pu.String()
		}
		match := PackageMatch{
			Package:   p.Name,
			Version:   p.Version,
			Ecosystem: p.Ecosystem(),
			PURL:      purl,
		}
		if len(p.Locations) > 0 {
			match.Locations = append([]string(nil), p.Locations...)
		}
		matches = append(matches, match)
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].Package == matches[j].Package {
			return matches[i].Version < matches[j].Version
		}
		return matches[i].Package < matches[j].Package
	})
	return matches
}

// listRepos returns the repositories for the given owner. If names are provided, only those
// repositories are returned; otherwise, all repositories for the owner are listed from GitHub.
func listRepos(ctx context.Context, client *github.Client, owner string, names []string) ([]repoTarget, error) {
	if client == nil {
		return nil, fmt.Errorf("github client is required")
	}
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, fmt.Errorf("owner is required")
	}

	if len(names) > 0 {
		uniq := uniqueNames(names)
		out := make([]repoTarget, 0, len(uniq))
		for _, name := range uniq {
			repo, _, err := client.Repositories.Get(ctx, owner, name)
			if err != nil {
				return nil, fmt.Errorf("get repo %s/%s: %w", owner, name, err)
			}
			cloneURL := repoCloneURL(repo)
			out = append(out, repoTarget{owner: owner, name: repo.GetName(), cloneURL: cloneURL})
		}
		return out, nil
	}

	repos, notFound, err := listOrgRepos(ctx, client, owner)
	if err != nil && !notFound {
		return nil, err
	}
	if notFound || len(repos) == 0 {
		return listUserRepos(ctx, client, owner)
	}
	return repos, nil
}

// listOrgRepos lists all repositories for the given organization.
func listOrgRepos(ctx context.Context, client *github.Client, org string) ([]repoTarget, bool, error) {
	opts := &github.RepositoryListByOrgOptions{Type: "all", ListOptions: github.ListOptions{PerPage: 100}}
	var out []repoTarget
	for {
		repos, resp, err := client.Repositories.ListByOrg(ctx, org, opts)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				return nil, true, nil
			}
			return nil, false, fmt.Errorf("list org repos: %w", err)
		}
		for _, repo := range repos {
			if repo == nil {
				continue
			}
			out = append(out, repoTarget{owner: org, name: repo.GetName(), cloneURL: repoCloneURL(repo)})
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return out, false, nil
}

// listUserRepos lists all repositories for the given user.
func listUserRepos(ctx context.Context, client *github.Client, user string) ([]repoTarget, error) {
	opts := &github.RepositoryListOptions{Type: "owner", ListOptions: github.ListOptions{PerPage: 100}}
	var out []repoTarget
	for {
		repos, resp, err := client.Repositories.List(ctx, user, opts)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf("user %s not found", user)
			}
			return nil, fmt.Errorf("list user repos: %w", err)
		}
		for _, repo := range repos {
			if repo == nil {
				continue
			}
			out = append(out, repoTarget{owner: user, name: repo.GetName(), cloneURL: repoCloneURL(repo)})
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return out, nil
}

// repoCloneURL returns the best available clone URL for the repository.
func repoCloneURL(repo *github.Repository) string {
	if repo == nil {
		return ""
	}
	if u := strings.TrimSpace(repo.GetCloneURL()); u != "" {
		return u
	}
	if u := strings.TrimSpace(repo.GetHTMLURL()); u != "" {
		return u + ".git"
	}
	if u := strings.TrimSpace(repo.GetSSHURL()); u != "" {
		return u
	}
	return ""
}

// uniqueNames returns a sorted list of unique, trimmed names from the input.
func uniqueNames(names []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// newGitHubClient constructs a GitHub client using the provided token.
func newGitHubClient(ctx context.Context, token string) *github.Client {
	retryableClient := retryablehttp.NewClient()
	retryableClient.Logger = nil
	retryableClient.HTTPClient = cleanhttp.DefaultPooledClient()

	if token == "" {
		return github.NewClient(retryableClient.StandardClient())
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, retryableClient.StandardClient())
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}
