package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	pb "deps.dev/api/v3"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v63/github"
	"github.com/google/osv-scalibr/extractor"
	scalibrlog "github.com/google/osv-scalibr/log"
	analysis "github.com/picatz/deputy/internal/analysis"
	cmp "github.com/picatz/deputy/internal/compare"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/logs"
	"github.com/picatz/deputy/internal/repository"
	"github.com/picatz/deputy/internal/repository/workspace"
	"golang.org/x/mod/module"
	"golang.org/x/oauth2"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type dependencyRow struct {
	Project     string
	PackageName string
	Version     string
	Licenses    []string
	Ecosystem   string
}

type repoTarget struct {
	org           string
	name          string
	cloneURL      string
	defaultBranch string
}

type licenseResolver func(context.Context, *extractor.Package) []string

var httpClient = &http.Client{Timeout: 5 * time.Second}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := run(ctx); err != nil {
		log.Fatalf("github-org-inventory: %v", err)
	}
}

func run(ctx context.Context) error {
	var (
		orgFlag         string
		repoFlag        string
		outputDir       string
		ecosystemsFlag  string
		concurrency     int
		cloneInMemory   bool
		includeForks    bool
		includeArchived bool
		licenseScan     bool
		logLevel        string
	)

	flag.StringVar(&orgFlag, "org", "", "GitHub organization to inventory (required unless --repo is set)")
	flag.StringVar(&repoFlag, "repo", "", "Single repository in owner/name form (overrides --org when set)")
	flag.StringVar(&outputDir, "out", "inventory-output", "Directory to write ecosystem CSV files into (org/repo subfolders will be created)")
	flag.StringVar(&ecosystemsFlag, "ecosystems", "all", "Comma-separated ecosystems to scan (use 'all' for default)")
	flag.IntVar(&concurrency, "concurrency", runtime.NumCPU(), "Number of concurrent repository scans")
	flag.BoolVar(&cloneInMemory, "in-memory", false, "Clone repositories into memory instead of temporary directories")
	flag.BoolVar(&includeForks, "include-forks", false, "Include forked repositories in the inventory")
	flag.BoolVar(&includeArchived, "include-archived", false, "Include archived repositories in the inventory")
	flag.BoolVar(&licenseScan, "license-scan", false, "Fetch licenses remotely when missing (slower). Defaults to package metadata only")
	flag.StringVar(&logLevel, "log-level", "info", "Log level: debug|info|warn|error")
	flag.Parse()

	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return errors.New("GITHUB_TOKEN is required for GitHub API access and clone authentication")
	}

	ecosystems := parseEcosystems(ecosystemsFlag)

	switch {
	case repoFlag == "" && orgFlag == "":
		return errors.New("either --org or --repo must be provided")
	case repoFlag != "" && strings.Count(repoFlag, "/") != 1:
		return fmt.Errorf("--repo must be in owner/name form, got %q", repoFlag)
	}

	logger, err := configureLogging(logLevel)
	if err != nil {
		return err
	}
	ctx = logs.WithContext(ctx, logger)
	attachScalibrLogger(logger)

	client := newGitHubClient(ctx, token)
	if client == nil {
		return errors.New("failed to construct GitHub client")
	}

	var targets []repoTarget
	if repoFlag != "" {
		owner, name, _ := strings.Cut(repoFlag, "/")
		t, err := getSingleRepo(ctx, client, owner, name)
		if err != nil {
			return err
		}
		targets = []repoTarget{t}
	} else {
		var err error
		targets, err = listOrgRepos(ctx, client, orgFlag, includeForks, includeArchived)
		if err != nil {
			return err
		}
	}

	outputDir = withTargetSubdir(outputDir, orgFlag, targets)

	if len(targets) == 0 {
		return fmt.Errorf("no repositories found for %q", cmpNonEmpty(repoFlag, orgFlag))
	}

	logs.Info(ctx, "planning inventory",
		"repo_count", len(targets),
		"ecosystems", displayEcosystems(ecosystems),
		"license_scan", licenseScan,
		"in_memory", cloneInMemory,
	)

	resolver := defaultLicenseResolver(licenseScan)
	rowsByEco := map[string][]dependencyRow{}
	var mu sync.Mutex
	successful := 0

	g, ctx := errgroup.WithContext(ctx)
	if concurrency <= 0 {
		concurrency = 1
	}
	g.SetLimit(concurrency)

	for _, target := range targets {
		g.Go(func() error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			logs.Info(ctx, "scanning repository", "owner", target.org, "name", target.name)
			repoRows, err := scanRepo(ctx, target, token, cloneInMemory, ecosystems, resolver)
			if err != nil {
				logs.Warn(ctx, "scan failed", "owner", target.org, "name", target.name, "error", err)
				return nil
			}
			mu.Lock()
			for eco, rows := range repoRows {
				rowsByEco[eco] = mergeRows(rowsByEco[eco], rows)
			}
			successful++
			mu.Unlock()
			logs.Info(ctx, "completed repository", "owner", target.org, "name", target.name)
			return nil
		})
	}

	_ = g.Wait()

	if successful == 0 {
		return errors.New("all repository scans failed")
	}

	if err := writeCSVs(rowsByEco, outputDir); err != nil {
		return err
	}

	log.Printf("wrote %d ecosystem CSVs to %s", len(rowsByEco), outputDir)
	return nil
}

func scanRepo(ctx context.Context, target repoTarget, token string, inMemory bool, ecosystems []string, resolve licenseResolver) (map[string][]dependencyRow, error) {
	if target.cloneURL == "" {
		return nil, fmt.Errorf("missing clone URL for %s/%s", target.org, target.name)
	}

	start := time.Now()
	cloneOpts := &git.CloneOptions{
		URL:          target.cloneURL,
		Depth:        1,
		SingleBranch: true,
		Tags:         git.NoTags,
		Auth:         githubAuth(token, target.cloneURL),
	}
	if target.defaultBranch != "" {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(target.defaultBranch)
	}

	src, err := repository.Clone(ctx, cloneOpts, inMemory)
	if err != nil {
		return nil, fmt.Errorf("clone: %w", err)
	}
	defer src.Close()

	rows, err := inventoryFromWorkspace(ctx, target.name, src.Workspace, ecosystems, resolve)
	logs.Info(ctx, "inventory complete",
		"owner", target.org,
		"name", target.name,
		"elapsed_ms", time.Since(start).Milliseconds(),
	)
	return rows, err
}

func inventoryFromWorkspace(ctx context.Context, repoName string, ws workspace.FS, ecosystems []string, resolve licenseResolver) (map[string][]dependencyRow, error) {
	start := time.Now()
	pkgs, err := inv.ScanPackagesWorking(ctx, ws, inv.ScanOptions{Ecosystems: ecosystems})
	if err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	logs.Info(ctx, "inventory scan finished",
		"repo", repoName,
		"packages", len(pkgs),
		"elapsed_ms", time.Since(start).Milliseconds(),
	)
	return collectRowsFromPackages(ctx, repoName, pkgs, resolve), nil
}

func collectRowsFromPackages(ctx context.Context, repoName string, pkgs []*extractor.Package, resolve licenseResolver) map[string][]dependencyRow {
	if resolve == nil {
		resolve = defaultLicenseResolver(false)
	}
	rowsByEco := make(map[string][]dependencyRow)
	seen := make(map[string]struct{})
	missingLicense := 0

	for _, p := range pkgs {
		if p == nil || strings.TrimSpace(p.Name) == "" {
			continue
		}
		name := strings.TrimSpace(p.Name)
		version := strings.TrimSpace(p.Version)
		if eco := canonicalEcosystem(p); eco == "go" && isLocalGoModule(name) {
			logs.Debug(ctx, "skipping local go module", "repo", repoName, "name", name)
			continue
		}
		if strings.EqualFold(name, "unknown") || name == "" {
			logs.Debug(ctx, "skipping package with unknown name", "repo", repoName, "ecosystem", canonicalEcosystem(p))
			continue
		}
		if strings.EqualFold(version, "unknown") || version == "" {
			logs.Debug(ctx, "skipping package with unknown version", "repo", repoName, "ecosystem", canonicalEcosystem(p), "name", name)
			continue
		}
		eco := canonicalEcosystem(p)
		key := fmt.Sprintf("%s|%s|%s|%s", eco, repoName, name, version)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		licenses := resolve(ctx, p)
		if len(normalizeLicenses(licenses)) == 0 {
			missingLicense++
		}
		rowsByEco[eco] = append(rowsByEco[eco], dependencyRow{
			Project:     repoName,
			PackageName: name,
			Version:     version,
			Licenses:    normalizeLicenses(licenses),
			Ecosystem:   eco,
		})
	}

	logs.Info(ctx, "package rows collected",
		"repo", repoName,
		"packages", len(pkgs),
		"ecosystems", len(rowsByEco),
		"missing_license_rows", missingLicense,
	)

	for eco := range rowsByEco {
		sort.Slice(rowsByEco[eco], func(i, j int) bool {
			if rowsByEco[eco][i].Project == rowsByEco[eco][j].Project {
				if rowsByEco[eco][i].PackageName == rowsByEco[eco][j].PackageName {
					return rowsByEco[eco][i].Version < rowsByEco[eco][j].Version
				}
				return rowsByEco[eco][i].PackageName < rowsByEco[eco][j].PackageName
			}
			return rowsByEco[eco][i].Project < rowsByEco[eco][j].Project
		})
	}

	return rowsByEco
}

func mergeRows(dst, src []dependencyRow) []dependencyRow {
	if len(src) == 0 {
		return dst
	}
	seen := make(map[string]struct{}, len(dst))
	for _, row := range dst {
		seen[rowKey(row)] = struct{}{}
	}
	for _, row := range src {
		key := rowKey(row)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		dst = append(dst, row)
	}
	sort.Slice(dst, func(i, j int) bool {
		if dst[i].Project == dst[j].Project {
			if dst[i].PackageName == dst[j].PackageName {
				return dst[i].Version < dst[j].Version
			}
			return dst[i].PackageName < dst[j].PackageName
		}
		return dst[i].Project < dst[j].Project
	})
	return dst
}

func rowKey(row dependencyRow) string {
	return fmt.Sprintf("%s|%s|%s|%s", row.Ecosystem, row.Project, row.PackageName, row.Version)
}

func writeCSVs(rows map[string][]dependencyRow, outputDir string) error {
	if len(rows) == 0 {
		return errors.New("no dependency rows to write")
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	for eco, entries := range rows {
		filename := filepath.Join(outputDir, fmt.Sprintf("%s.csv", sanitizeEcosystemName(eco)))
		f, err := os.Create(filename)
		if err != nil {
			return fmt.Errorf("create %s: %w", filename, err)
		}

		w := csv.NewWriter(f)
		if err := w.Write([]string{"Project", "Package Name", "Version", "License"}); err != nil {
			f.Close()
			return fmt.Errorf("write header for %s: %w", filename, err)
		}
		for _, row := range entries {
			license := strings.Join(normalizeLicenses(row.Licenses), ";")
			if license == "" {
				license = "?"
			}
			record := []string{row.Project, row.PackageName, row.Version, license}
			if err := w.Write(record); err != nil {
				f.Close()
				return fmt.Errorf("write row for %s: %w", filename, err)
			}
		}
		w.Flush()
		if err := w.Error(); err != nil {
			f.Close()
			return fmt.Errorf("flush %s: %w", filename, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close %s: %w", filename, err)
		}
		logs.Info(context.Background(), "csv written", "ecosystem", eco, "rows", len(entries), "path", filename)
	}
	return nil
}

func parseEcosystems(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "all") {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || strings.EqualFold(p, "all") {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

func canonicalEcosystem(p *extractor.Package) string {
	raw := strings.TrimSpace(p.Ecosystem())
	if raw == "" || strings.EqualFold(raw, "unknown") {
		raw = strings.TrimSpace(p.PURLType)
	}
	rawLower := strings.ToLower(raw)
	switch rawLower {
	case "golang", "go":
		return "go"
	case "pypi", "python":
		return "python"
	case "npm", "node", "nodejs", "javascript":
		return "javascript"
	case "rubygems", "ruby":
		return "ruby"
	case "maven":
		return "java"
	case "crates.io", "cargo", "rust":
		return "rust"
	case "nuget":
		return "dotnet"
	case "packagist", "composer", "php":
		return "php"
	default:
		if raw == "" {
			return "unknown"
		}
		return rawLower
	}
}

func sanitizeEcosystemName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-", "*", "-", "?", "-", "\"", "", "<", "", ">", "", "|", "-")
	return replacer.Replace(name)
}

func withTargetSubdir(base string, org string, targets []repoTarget) string {
	if len(targets) == 0 {
		return base
	}
	owner := sanitizeEcosystemName(org)
	if owner == "" {
		owner = sanitizeEcosystemName(targets[0].org)
	}
	if owner == "" {
		owner = "unknown-owner"
	}
	if len(targets) == 1 {
		repo := sanitizeEcosystemName(targets[0].name)
		if repo == "" {
			repo = "unknown-repo"
		}
		return filepath.Join(base, owner, repo)
	}
	return filepath.Join(base, owner)
}

func normalizeLicenses(licenses []string) []string {
	if len(licenses) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(licenses))
	for _, l := range licenses {
		l = strings.TrimSpace(l)
		if l == "" || l == "?" {
			continue
		}
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

func defaultLicenseResolver(deepScan bool) licenseResolver {
	var (
		sf         singleflight.Group
		cache      sync.Map
		clientOnce sync.Once
		client     pb.InsightsClient
	)

	getClient := func() pb.InsightsClient {
		clientOnce.Do(func() {
			client = newDepsDevClient()
		})
		return client
	}

	return func(ctx context.Context, pkg *extractor.Package) []string {
		if pkg == nil {
			return nil
		}
		if ctx.Err() != nil {
			return nil
		}
		if l := knownLicenses(pkg); len(l) > 0 {
			return l
		}
		if cleaned := normalizeLicenses(pkg.Licenses); len(cleaned) > 0 {
			return cleaned
		}
		if !deepScan {
			return nil
		}

		eco := canonicalEcosystem(pkg)
		module := modulePathFromPackage(pkg)
		version := strings.TrimSpace(pkg.Version)
		if eco == "go" && version != "" && !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
		key := pkg.Name + "|" + version + "|" + eco

		if v, ok := cache.Load(key); ok {
			logs.Debug(ctx, "license cache hit", "module", module, "version", version)
			return cloneStrings(v.([]string))
		}

		res, _, _ := sf.Do(key, func() (interface{}, error) {
			if ctx.Err() != nil {
				return []string{}, ctx.Err()
			}
			logs.Debug(ctx, "license lookup starting", "name", pkg.Name, "version", version, "ecosystem", eco)
			licenses := lookupDepsDevLicenses(ctx, getClient(), pkg, eco, module)
			if len(licenses) == 0 && eco == "go" {
				for _, parent := range ancestorModules(module) {
					licenses = lookupDepsDevLicenses(ctx, getClient(), pkgWithModule(pkg, parent), eco, parent)
					if len(licenses) > 0 {
						break
					}
				}
			}
			if len(licenses) == 0 && eco == "go" && module != "" {
				logs.Debug(ctx, "license lookup falling back to remote scan", "module", module, "version", version)
				licenses = lookupRemoteLicenses(ctx, module, version)
				if len(licenses) == 0 {
					if gp := lookupGoProxyLicense(ctx, module, version); len(gp) > 0 {
						licenses = gp
					}
				}
			}
			if len(licenses) == 0 && eco == "rust" {
				if rust := lookupCratesLicense(ctx, pkg.Name, version); len(rust) > 0 {
					licenses = rust
				}
			}
			if len(licenses) == 0 && eco == "php" {
				if php := lookupPackagistLicense(ctx, pkg.Name, version); len(php) > 0 {
					licenses = php
				}
			}
			if licenses == nil {
				licenses = []string{}
			}
			cache.Store(key, licenses)
			return licenses, nil
		})
		if v, ok := res.([]string); ok {
			return cloneStrings(v)
		}
		return nil
	}
}

func modulePathFromPackage(pkg *extractor.Package) string {
	if pkg == nil {
		return ""
	}
	// For Go, scalibr reports the module path in Package.Name for go.mod entries,
	// including nested modules (e.g., github.com/Azure/azure-sdk-for-go/sdk/azcore).
	// Preserve the full path so deps.dev lookups work for multi-module repos.
	if canonicalEcosystem(pkg) == "go" {
		return strings.TrimSpace(pkg.Name)
	}
	info := cmp.ParseGoPackage(pkg)
	return cmp.GetModuleRoot(info.CanonicalName)
}

// ancestorModules returns parent module paths for a given module, excluding the original.
func ancestorModules(module string) []string {
	if module == "" {
		return nil
	}
	parts := strings.Split(module, "/")
	if len(parts) < 3 { // host/user/repo minimum
		return nil
	}
	var out []string
	for i := len(parts) - 1; i >= 3; i-- {
		out = append(out, strings.Join(parts[:i], "/"))
	}
	return out
}

// pkgWithModule returns a shallow copy of pkg with Name replaced by module path.
func pkgWithModule(pkg *extractor.Package, module string) *extractor.Package {
	if pkg == nil {
		return nil
	}
	cp := *pkg
	if module != "" {
		cp.Name = module
	}
	return &cp
}

// knownLicenses returns hardcoded licenses for well-known packages that lack metadata.
func knownLicenses(pkg *extractor.Package) []string {
	if pkg == nil {
		return nil
	}
	name := strings.TrimSpace(pkg.Name)
	version := strings.TrimSpace(pkg.Version)
	ecosystem := canonicalEcosystem(pkg)
	// Go standard library
	if ecosystem == "go" && strings.EqualFold(name, "stdlib") {
		return []string{"BSD-3-Clause"}
	}
	// Go toolchain module (go@1.x)
	if ecosystem == "go" && strings.EqualFold(name, "go") {
		return []string{"BSD-3-Clause"}
	}
	// Known legacy module missing embedded license but licensed via upstream repo.
	// See https://github.com/mattn/go-localereader/pull/1
	if ecosystem == "go" && strings.EqualFold(name, "github.com/mattn/go-localereader") && version == "0.0.1" {
		return []string{"MIT"}
	}
	return nil
}

// isLocalGoModule reports whether a module path appears to be a local/internal module
// (no domain-like prefix). Such modules are typically not published and lack registry
// license metadata; we skip them to avoid noisy \"?\" entries.
func isLocalGoModule(path string) bool {
	if path == "" {
		return true
	}
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return true
	}
	host := parts[0]
	return !strings.Contains(host, ".")
}

func displayEcosystems(ecosystems []string) string {
	if len(ecosystems) == 0 {
		return "all"
	}
	return strings.Join(ecosystems, ",")
}

func cmpNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func listOrgRepos(ctx context.Context, client *github.Client, org string, includeForks bool, includeArchived bool) ([]repoTarget, error) {
	org = strings.TrimSpace(org)
	if org == "" {
		return nil, errors.New("organization name is required")
	}
	opts := &github.RepositoryListByOrgOptions{Type: "all", ListOptions: github.ListOptions{PerPage: 100}}
	var out []repoTarget
	for {
		repos, resp, err := client.Repositories.ListByOrg(ctx, org, opts)
		if err != nil {
			return nil, fmt.Errorf("list org repos: %w", err)
		}
		for _, repo := range repos {
			if repo == nil {
				continue
			}
			if !includeForks && repo.GetFork() {
				continue
			}
			if !includeArchived && repo.GetArchived() {
				continue
			}
			out = append(out, repoTarget{
				org:           org,
				name:          repo.GetName(),
				cloneURL:      repoCloneURL(repo),
				defaultBranch: repo.GetDefaultBranch(),
			})
		}
		if resp == nil || resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return out, nil
}

func getSingleRepo(ctx context.Context, client *github.Client, owner, name string) (repoTarget, error) {
	repo, _, err := client.Repositories.Get(ctx, owner, name)
	if err != nil {
		return repoTarget{}, fmt.Errorf("get repo %s/%s: %w", owner, name, err)
	}
	return repoTarget{
		org:           owner,
		name:          repo.GetName(),
		cloneURL:      repoCloneURL(repo),
		defaultBranch: repo.GetDefaultBranch(),
	}, nil
}

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

func newGitHubClient(ctx context.Context, token string) *github.Client {
	if token == "" {
		return github.NewClient(nil)
	}
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

// lookupDepsDevLicenses fetches SPDX IDs from deps.dev with a short timeout.
func lookupDepsDevLicenses(ctx context.Context, client pb.InsightsClient, pkg *extractor.Package, eco string, module string) []string {
	if client == nil || pkg == nil {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	version := strings.TrimSpace(pkg.Version)
	if eco == "go" && version != "" && !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	system, name := depsDevKeyFromPackage(pkg, eco, module)
	if system == pb.System_SYSTEM_UNSPECIFIED || name == "" || version == "" {
		return nil
	}

	req := &pb.GetVersionRequest{
		VersionKey: &pb.VersionKey{
			System:  system,
			Name:    name,
			Version: version,
		},
	}
	resp, err := client.GetVersion(cctx, req)
	if err != nil || resp == nil {
		return nil
	}
	return normalizeLicenses(resp.Licenses)
}

// lookupRemoteLicenses performs a best-effort remote scan with a timeout.
func lookupRemoteLicenses(ctx context.Context, module, version string) []string {
	if module == "" || version == "" {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return normalizeLicenses(analysis.RemoteModuleLicenseScan(cctx, module, version))
}

// lookupGoProxyLicense downloads the module zip from the Go proxy and scans license files.
func lookupGoProxyLicense(ctx context.Context, modulePath, version string) []string {
	if modulePath == "" || version == "" {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	encPath, err := module.EscapePath(modulePath)
	if err != nil {
		return nil
	}
	url := fmt.Sprintf("https://proxy.golang.org/%s/@v/%s.zip", encPath, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20)) // cap at 20MB
	if err != nil || len(data) == 0 {
		return nil
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	var out []string
	for _, f := range zr.File {
		name := strings.ToLower(f.Name)
		for _, candidate := range analysis.DefaultLicenseFilenamesForScan() {
			if strings.HasSuffix(name, strings.ToLower(candidate)) {
				rc, err := f.Open()
				if err != nil {
					continue
				}
				content, _ := io.ReadAll(rc)
				rc.Close()
				out = append(out, analysis.DetectLicenseIDs(content)...)
			}
		}
	}
	return normalizeLicenses(out)
}

// lookupCratesLicense queries crates.io for license metadata.
func lookupCratesLicense(ctx context.Context, name, version string) []string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	url := fmt.Sprintf("https://crates.io/api/v1/crates/%s/%s", name, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var payload struct {
		Version struct {
			License string `json:"license"`
		} `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}
	return normalizeLicenses(splitLicenseString(payload.Version.License))
}

// lookupPackagistLicense queries packagist.org for license metadata.
func lookupPackagistLicense(ctx context.Context, name, version string) []string {
	name = strings.ToLower(strings.TrimSpace(name))
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	if l := lookupPackagistP2(ctx, name, version); len(l) > 0 {
		return l
	}
	return lookupPackagistLegacy(ctx, name, version)
}

// lookupPackagistP2 queries the p2 endpoint, which returns an array of versions.
func lookupPackagistP2(ctx context.Context, name, version string) []string {
	url := fmt.Sprintf("https://repo.packagist.org/p2/%s.json", name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var payload struct {
		Packages map[string][]struct {
			Version           string   `json:"version"`
			VersionNormalized string   `json:"version_normalized"`
			License           []string `json:"license"`
		} `json:"packages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}
	versions, ok := payload.Packages[name]
	if !ok {
		for k, v := range payload.Packages {
			if strings.EqualFold(k, name) {
				versions = v
				break
			}
		}
	}
	if len(versions) == 0 {
		return nil
	}
	tryVersions := []string{version}
	if strings.HasPrefix(version, "v") {
		tryVersions = append(tryVersions, strings.TrimPrefix(version, "v"))
	} else {
		tryVersions = append(tryVersions, "v"+version)
	}
	for _, v := range tryVersions {
		for _, pkg := range versions {
			if pkg.Version == v || pkg.VersionNormalized == v {
				if l := normalizeLicenses(pkg.License); len(l) > 0 {
					return l
				}
			}
		}
	}
	// Fallback to first available license
	for _, pkg := range versions {
		if l := normalizeLicenses(pkg.License); len(l) > 0 {
			return l
		}
	}
	return nil
}

// lookupPackagistLegacy queries the legacy p endpoint.
func lookupPackagistLegacy(ctx context.Context, name, version string) []string {
	url := fmt.Sprintf("https://repo.packagist.org/p/%s.json", name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var payload struct {
		Packages map[string]map[string]struct {
			License           []string `json:"license"`
			VersionNormalized string   `json:"version_normalized"`
		} `json:"packages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}
	versions := payload.Packages[name]
	if versions == nil {
		for k, v := range payload.Packages {
			if strings.EqualFold(k, name) {
				versions = v
				break
			}
		}
	}
	if versions == nil {
		return nil
	}
	tryVersions := []string{version}
	if strings.HasPrefix(version, "v") {
		tryVersions = append(tryVersions, strings.TrimPrefix(version, "v"))
	} else {
		tryVersions = append(tryVersions, "v"+version)
	}
	for _, v := range tryVersions {
		if pkg, ok := versions[v]; ok {
			return normalizeLicenses(pkg.License)
		}
	}
	for _, pkg := range versions {
		if pkg.VersionNormalized == version || pkg.VersionNormalized == strings.TrimPrefix(version, "v") {
			if l := normalizeLicenses(pkg.License); len(l) > 0 {
				return l
			}
		}
	}
	for _, pkg := range versions {
		if l := normalizeLicenses(pkg.License); len(l) > 0 {
			return l
		}
	}
	return nil
}

// splitLicenseString splits a license string like "Apache-2.0 OR MIT" into parts.
func splitLicenseString(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ';', ',', '|', '/', '\\':
			return true
		}
		return false
	})
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = strings.TrimPrefix(p, "OR")
		p = strings.TrimPrefix(p, "AND")
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// depsDevKeyFromPackage maps an extractor package to deps.dev system/name values.
func depsDevKeyFromPackage(pkg *extractor.Package, eco string, module string) (pb.System, string) {
	if pkg == nil {
		return pb.System_SYSTEM_UNSPECIFIED, ""
	}
	if eco == "go" && module != "" {
		return pb.System_GO, module
	}

	if pu := pkg.PURL(); pu != nil {
		switch pu.Type {
		case "golang":
			name := module
			if name == "" {
				name = pu.Namespace + "/" + pu.Name
			}
			return pb.System_GO, name
		case "npm":
			name := pu.Name
			if pu.Namespace != "" {
				name = "@" + pu.Namespace + "/" + pu.Name
			}
			return pb.System_NPM, name
		case "pypi":
			return pb.System_PYPI, strings.ToLower(pu.Name)
		case "maven":
			ns := strings.TrimSpace(pu.Namespace)
			if ns == "" {
				return pb.System_MAVEN, pu.Name
			}
			return pb.System_MAVEN, ns + ":" + pu.Name
		case "nuget":
			return pb.System_NUGET, pu.Name
		case "rubygems":
			return pb.System_RUBYGEMS, pu.Name
		}
	}

	switch strings.ToLower(eco) {
	case "go":
		return pb.System_GO, module
	case "npm", "javascript":
		return pb.System_NPM, pkg.Name
	case "python", "pypi":
		return pb.System_PYPI, strings.ToLower(pkg.Name)
	case "java", "maven":
		return pb.System_MAVEN, pkg.Name
	case "nuget", "dotnet":
		return pb.System_NUGET, pkg.Name
	case "ruby", "rubygems":
		return pb.System_RUBYGEMS, pkg.Name
	default:
		return pb.System_SYSTEM_UNSPECIFIED, ""
	}
}

// newDepsDevClient constructs a deps.dev gRPC client (best-effort). Returns nil on failure.
func newDepsDevClient() pb.InsightsClient {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil
	}
	dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dctx, "api.deps.dev:443", grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(pool, "")), grpc.WithBlock())
	if err != nil {
		logs.Debug(context.Background(), "deps.dev dial failed", "error", err)
		return nil
	}
	return pb.NewInsightsClient(conn)
}

// configureLogging builds a slog logger and sets it as default for both slog and Deputy logs.
func configureLogging(levelStr string) (*slog.Logger, error) {
	level, err := logs.ParseLevel(levelStr)
	if err != nil {
		return nil, err
	}
	logger := logs.New(logs.Options{
		Level:        level,
		Format:       "text",
		ColorEnabled: true,
	})
	logs.SetDefault(logger)
	slog.SetDefault(logger)
	return logger, nil
}

// attachScalibrLogger routes SCALIBR logs through slog so demo output is centralized.
func attachScalibrLogger(logger *slog.Logger) {
	if logger == nil {
		return
	}
	scalibrlog.SetLogger(&scalibrSlogLogger{log: logger})
}

type scalibrSlogLogger struct {
	log *slog.Logger
}

func (l *scalibrSlogLogger) Errorf(format string, args ...any) {
	l.logf(slog.LevelError, format, args...)
}
func (l *scalibrSlogLogger) Error(args ...any) { l.logArgs(slog.LevelError, args...) }
func (l *scalibrSlogLogger) Warnf(format string, args ...any) {
	l.logf(slog.LevelWarn, format, args...)
}
func (l *scalibrSlogLogger) Warn(args ...any) { l.logArgs(slog.LevelWarn, args...) }
func (l *scalibrSlogLogger) Infof(format string, args ...any) {
	l.logf(slog.LevelInfo, format, args...)
}
func (l *scalibrSlogLogger) Info(args ...any) { l.logArgs(slog.LevelInfo, args...) }
func (l *scalibrSlogLogger) Debugf(format string, args ...any) {
	l.logf(slog.LevelDebug, format, args...)
}
func (l *scalibrSlogLogger) Debug(args ...any) { l.logArgs(slog.LevelDebug, args...) }

func (l *scalibrSlogLogger) logf(level slog.Level, format string, args ...any) {
	if l == nil || l.log == nil {
		return
	}
	if !l.log.Enabled(context.Background(), level) {
		return
	}
	l.log.Log(context.Background(), level, fmt.Sprintf(format, args...))
}

func (l *scalibrSlogLogger) logArgs(level slog.Level, args ...any) {
	if l == nil || l.log == nil {
		return
	}
	if !l.log.Enabled(context.Background(), level) {
		return
	}
	l.log.Log(context.Background(), level, fmt.Sprint(args...))
}

// cloneStrings copies a string slice to avoid sharing mutable backing arrays.
func cloneStrings(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}
