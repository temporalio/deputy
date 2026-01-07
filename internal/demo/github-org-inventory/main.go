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
	"slices"
	"strings"
	"sync"
	"time"

	pb "deps.dev/api/v3"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-github/v63/github"
	"github.com/google/osv-scalibr/extractor"
	scalibrlog "github.com/google/osv-scalibr/log"
	"github.com/picatz/deputy/internal/compare"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/license"
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
	skippedUnresolvable := 0

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

		// Skip unresolvable entries based on ecosystem
		if shouldSkipUnresolvable(eco, name, version) {
			logs.Debug(ctx, "skipping unresolvable package", "repo", repoName, "ecosystem", eco, "name", name, "version", version)
			skippedUnresolvable++
			continue
		}

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
		"skipped_unresolvable", skippedUnresolvable,
	)

	for eco := range rowsByEco {
		slices.SortFunc(rowsByEco[eco], func(a, b dependencyRow) int {
			if c := strings.Compare(a.Project, b.Project); c != 0 {
				return c
			}
			if c := strings.Compare(a.PackageName, b.PackageName); c != 0 {
				return c
			}
			return strings.Compare(a.Version, b.Version)
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
	slices.SortFunc(dst, func(a, b dependencyRow) int {
		if c := strings.Compare(a.Project, b.Project); c != 0 {
			return c
		}
		if c := strings.Compare(a.PackageName, b.PackageName); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
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
	slices.Sort(out)
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
	case "dart", "pub", "flutter":
		return "dart"
	case "cocoapods", "pod", "pods":
		return "cocoapods"
	case "hex", "hexpm":
		return "hex"
	case "docker", "oci":
		return "container"
	case "githubactions", "github-actions", "github actions", "gha":
		return "githubactions"
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
	slices.Sort(out)
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
			return slices.Clone(v.([]string))
		}

		res, _, _ := sf.Do(key, func() (any, error) {
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
			if len(licenses) == 0 && eco == "dart" {
				if dart := license.LookupPubLicense(ctx, pkg.Name, version); len(dart) > 0 {
					licenses = dart
				}
			}
			if len(licenses) == 0 && eco == "cocoapods" {
				if pods := license.LookupCocoaPodsLicense(ctx, pkg.Name, version); len(pods) > 0 {
					licenses = pods
				}
			}
			if len(licenses) == 0 && eco == "hex" {
				if hex := license.LookupHexLicense(ctx, pkg.Name, version); len(hex) > 0 {
					licenses = hex
				}
			}
			// GitHub Actions: look up license from the action's GitHub repo
			if len(licenses) == 0 && eco == "githubactions" {
				licenses = resolveGitHubActionLicense(ctx, pkg.Name, version)
			}
			// Container images: check well-known licenses first, then fall back to GitHub lookups
			if len(licenses) == 0 && eco == "container" {
				licenses = resolveContainerLicense(ctx, pkg.Name, version)
			}
			if licenses == nil {
				licenses = []string{}
			}
			cache.Store(key, licenses)
			return licenses, nil
		})
		if v, ok := res.([]string); ok {
			return slices.Clone(v)
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
	info := compare.ParseGoPackage(pkg)
	return compare.GetModuleRoot(info.CanonicalName)
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

// lookupContainerLicense returns licenses for well-known container base images.
// Container images don't have a standardized license registry, so we maintain
// a list of common base images and their licenses.
func lookupContainerLicense(name, version string) []string {
	// Normalize the image name by removing common prefixes
	name = strings.TrimPrefix(name, "library/")
	name = strings.TrimPrefix(name, "docker.io/library/")
	name = strings.TrimPrefix(name, "docker.io/")

	// Extract the base image name (without tag/registry path for matching)
	// e.g., "gcr.io/distroless/static" -> check against "distroless/static"
	baseName := name
	if idx := strings.Index(name, "/"); idx != -1 {
		// Check if it looks like a registry prefix (contains dots)
		prefix := name[:idx]
		if strings.Contains(prefix, ".") {
			baseName = name[idx+1:]
		}
	}

	// Well-known container image licenses
	// Sources:
	// - Alpine: https://alpinelinux.org/about/ (MIT)
	// - Debian: https://www.debian.org/legal/licenses/ (various, primarily GPL)
	// - Ubuntu: https://ubuntu.com/legal/intellectual-property-policy (various, primarily GPL)
	// - Golang: https://golang.org/LICENSE (BSD-3-Clause)
	// - Python: https://docs.python.org/3/license.html (PSF-2.0)
	// - Node: https://github.com/nodejs/node/blob/main/LICENSE (MIT)
	// - Distroless: https://github.com/GoogleContainerTools/distroless (Apache-2.0)
	// - Chainguard: https://github.com/chainguard-images (Apache-2.0)
	// - Rust: https://www.rust-lang.org/policies/licenses (MIT OR Apache-2.0)
	// - Busybox: https://busybox.net/license.html (GPL-2.0)
	// - Nginx: https://nginx.org/LICENSE (BSD-2-Clause)
	// - Redis: https://redis.io/docs/about/license/ (BSD-3-Clause)
	// - Postgres: https://www.postgresql.org/about/licence/ (PostgreSQL)
	// - MySQL: https://www.mysql.com/about/legal/licensing/ (GPL-2.0)
	// - Grafana: https://github.com/grafana/grafana/blob/main/LICENSE (AGPL-3.0)
	knownLicenses := map[string][]string{
		// OS base images
		"alpine":           {"MIT"},
		"debian":           {"GPL-2.0"},
		"ubuntu":           {"GPL-2.0"},
		"centos":           {"GPL-2.0"},
		"fedora":           {"MIT"},
		"rockylinux":       {"BSD-3-Clause"},
		"almalinux":        {"GPL-2.0"},
		"amazonlinux":      {"GPL-2.0"},
		"oraclelinux":      {"GPL-2.0"},
		"busybox":          {"GPL-2.0"},
		"scratch":          {}, // No license needed for scratch
		"clearlinux":       {"Apache-2.0"},

		// Language runtime images
		"golang":           {"BSD-3-Clause"},
		"python":           {"PSF-2.0"},
		"node":             {"MIT"},
		"ruby":             {"Ruby", "BSD-2-Clause"},
		"rust":             {"MIT", "Apache-2.0"},
		"openjdk":          {"GPL-2.0-with-classpath-exception"},
		"eclipse-temurin":  {"GPL-2.0-with-classpath-exception"},
		"amazoncorretto":   {"GPL-2.0-with-classpath-exception"},
		"php":              {"PHP-3.01"},
		"perl":             {"Artistic-1.0", "GPL-1.0"},
		"gcc":              {"GPL-3.0"},
		"clang":            {"Apache-2.0"},
		"swift":            {"Apache-2.0"},
		"dotnet/sdk":       {"MIT"},
		"dotnet/runtime":   {"MIT"},
		"dotnet/aspnet":    {"MIT"},
		"mcr.microsoft.com/dotnet/sdk":     {"MIT"},
		"mcr.microsoft.com/dotnet/runtime": {"MIT"},
		"mcr.microsoft.com/dotnet/aspnet":  {"MIT"},

		// Distroless images (Google)
		"distroless/static":           {"Apache-2.0"},
		"distroless/base":             {"Apache-2.0"},
		"distroless/cc":               {"Apache-2.0"},
		"distroless/java":             {"Apache-2.0"},
		"distroless/nodejs":           {"Apache-2.0"},
		"distroless/python3":          {"Apache-2.0"},
		"distroless/static-debian11":  {"Apache-2.0"},
		"distroless/static-debian12":  {"Apache-2.0"},
		"distroless/base-debian11":    {"Apache-2.0"},
		"distroless/base-debian12":    {"Apache-2.0"},
		"distroless/nodejs20-debian11": {"Apache-2.0"},

		// Chainguard images
		"chainguard/static":        {"Apache-2.0"},
		"chainguard/go":            {"Apache-2.0"},
		"chainguard/python":        {"Apache-2.0"},
		"chainguard/node":          {"Apache-2.0"},
		"chainguard/glibc-dynamic": {"Apache-2.0"},

		// Database images
		"postgres":         {"PostgreSQL"},
		"mysql":            {"GPL-2.0"},
		"mariadb":          {"GPL-2.0"},
		"mongo":            {"SSPL-1.0"},
		"redis":            {"BSD-3-Clause"},
		"memcached":        {"BSD-3-Clause"},
		"elasticsearch":    {"Elastic-2.0"},
		"cassandra":        {"Apache-2.0"},

		// Web servers / proxies
		"nginx":            {"BSD-2-Clause"},
		"httpd":            {"Apache-2.0"},
		"traefik":          {"MIT"},
		"haproxy":          {"GPL-2.0"},
		"envoy":            {"Apache-2.0"},
		"caddy":            {"Apache-2.0"},

		// Observability
		"grafana/grafana":  {"AGPL-3.0"},
		"prom/prometheus":  {"Apache-2.0"},
		"jaegertracing/all-in-one": {"Apache-2.0"},

		// CI/CD tools
		"docker":           {"Apache-2.0"},
		"docker/compose":   {"Apache-2.0"},
		"hashicorp/vault":  {"BUSL-1.1"},
		"hashicorp/consul": {"BUSL-1.1"},
		"hashicorp/terraform": {"BUSL-1.1"},

		// Message queues
		"rabbitmq":         {"MPL-2.0"},
		"nats":             {"Apache-2.0"},
		"apache/kafka":     {"Apache-2.0"},
		"confluentinc/cp-kafka": {"Apache-2.0"},
		"zookeeper":        {"Apache-2.0"},

		// Package tools
		"maven":            {"Apache-2.0"},
		"gradle":           {"Apache-2.0"},
		"astral-sh/uv":     {"MIT", "Apache-2.0"},
	}

	// Try exact match first
	if lics, ok := knownLicenses[baseName]; ok {
		return lics
	}

	// Try with name as-is
	if lics, ok := knownLicenses[name]; ok {
		return lics
	}

	// Try matching just the image name (last component)
	parts := strings.Split(baseName, "/")
	shortName := parts[len(parts)-1]
	// Strip version suffix like "-slim", "-alpine", "-bullseye", etc.
	shortName = strings.Split(shortName, "-")[0]
	if lics, ok := knownLicenses[shortName]; ok {
		return lics
	}

	return nil
}

// resolveContainerLicense attempts to resolve a license for a container image.
// It uses a principled multi-layer approach:
//  1. OCI standard: Check org.opencontainers.image.licenses annotation (the official standard)
//  2. Well-known database: Check hardcoded licenses for common base images
//  3. Source repository: Look up license from GitHub for ghcr.io/quay.io images
func resolveContainerLicense(ctx context.Context, name, version string) []string {
	// Build full image reference
	imageRef := buildImageReference(name, version)

	// 1. First try OCI standard annotation (most principled approach)
	// The OCI Image Spec defines org.opencontainers.image.licenses for SPDX license expressions
	// See: https://github.com/opencontainers/image-spec/blob/main/annotations.md
	if lics := lookupOCILicenseAnnotation(ctx, imageRef); len(lics) > 0 {
		logs.Debug(ctx, "resolved container license from OCI annotation",
			"image", imageRef, "licenses", lics)
		return lics
	}

	// 2. Try well-known licenses database (practical fallback for common images)
	if lics := lookupContainerLicense(name, version); len(lics) > 0 {
		logs.Debug(ctx, "resolved container license from well-known database",
			"image", imageRef, "licenses", lics)
		return lics
	}

	// 3. Try to resolve from GitHub for ghcr.io images
	if strings.HasPrefix(name, "ghcr.io/") {
		// ghcr.io/owner/repo -> github.com/owner/repo
		parts := strings.SplitN(strings.TrimPrefix(name, "ghcr.io/"), "/", 3)
		if len(parts) >= 2 {
			owner, repo := parts[0], parts[1]
			// Strip any tag/digest from repo name if present
			if idx := strings.Index(repo, ":"); idx != -1 {
				repo = repo[:idx]
			}
			if idx := strings.Index(repo, "@"); idx != -1 {
				repo = repo[:idx]
			}
			modulePath := fmt.Sprintf("github.com/%s/%s", owner, repo)
			// Use empty version to get default branch
			if lics := license.RemoteModuleLicenseScan(ctx, modulePath, ""); len(lics) > 0 {
				logs.Debug(ctx, "resolved container license from GitHub source",
					"image", imageRef, "github", modulePath, "licenses", lics)
				return lics
			}
		}
	}

	// 4. Try to resolve from GitHub for quay.io images that might have GitHub sources
	if strings.HasPrefix(name, "quay.io/") {
		parts := strings.SplitN(strings.TrimPrefix(name, "quay.io/"), "/", 3)
		if len(parts) >= 2 {
			owner, repo := parts[0], parts[1]
			if idx := strings.Index(repo, ":"); idx != -1 {
				repo = repo[:idx]
			}
			if idx := strings.Index(repo, "@"); idx != -1 {
				repo = repo[:idx]
			}
			// Try common GitHub mappings
			modulePath := fmt.Sprintf("github.com/%s/%s", owner, repo)
			if lics := license.RemoteModuleLicenseScan(ctx, modulePath, ""); len(lics) > 0 {
				logs.Debug(ctx, "resolved container license from GitHub source",
					"image", imageRef, "github", modulePath, "licenses", lics)
				return lics
			}
		}
	}

	return nil
}

// buildImageReference constructs a full image reference from name and version/tag.
func buildImageReference(name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)

	// If name already contains a tag or digest, use it as-is
	if strings.Contains(name, ":") || strings.Contains(name, "@") {
		return name
	}

	// Add default registry for library images
	if !strings.Contains(name, "/") || strings.HasPrefix(name, "library/") {
		// Docker Hub official image
		if !strings.HasPrefix(name, "library/") {
			name = "library/" + name
		}
		name = "index.docker.io/" + name
	} else if !strings.Contains(strings.Split(name, "/")[0], ".") {
		// Docker Hub user image (no registry prefix)
		name = "index.docker.io/" + name
	}

	// Add tag/version
	if version != "" {
		// Check if version looks like a digest
		if strings.HasPrefix(version, "sha256:") {
			return name + "@" + version
		}
		return name + ":" + version
	}

	return name + ":latest"
}

// ociLicensesAnnotation is the OCI standard annotation key for image licenses.
// See: https://github.com/opencontainers/image-spec/blob/main/annotations.md
const ociLicensesAnnotation = "org.opencontainers.image.licenses"

// lookupOCILicenseAnnotation fetches the image config and reads the
// org.opencontainers.image.licenses annotation per the OCI Image Spec.
// This is the most principled approach as it uses the official standard.
func lookupOCILicenseAnnotation(ctx context.Context, imageRef string) []string {
	if imageRef == "" {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}

	// Use a short timeout for remote lookups
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Fetch image config using crane (from go-containerregistry)
	// This only fetches the config, not the full image layers
	configBytes, err := crane.Config(imageRef, crane.WithContext(ctx))
	if err != nil {
		logs.Debug(ctx, "failed to fetch OCI config for license lookup",
			"image", imageRef, "error", err)
		return nil
	}

	// Parse the config to extract labels
	var config struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		logs.Debug(ctx, "failed to parse OCI config",
			"image", imageRef, "error", err)
		return nil
	}

	// Check for the OCI license annotation
	licenseValue := config.Config.Labels[ociLicensesAnnotation]
	if licenseValue == "" {
		return nil
	}

	// Parse SPDX license expression
	return parseOCILicenseExpression(licenseValue)
}

// parseOCILicenseExpression parses an SPDX license expression into individual license identifiers.
// The OCI spec recommends SPDX expressions like "Apache-2.0" or "MIT OR Apache-2.0".
func parseOCILicenseExpression(expr string) []string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}

	// Split on common SPDX expression operators and separators
	// Handle: "MIT", "MIT OR Apache-2.0", "MIT AND GPL-2.0", "MIT, Apache-2.0"
	var licenses []string
	seen := make(map[string]bool)

	// Split on OR, AND, comma, semicolon while preserving license IDs
	parts := strings.FieldsFunc(expr, func(r rune) bool {
		return r == ',' || r == ';'
	})

	for _, part := range parts {
		// Further split on " OR " and " AND " (with spaces to avoid splitting license names)
		subparts := splitOnSPDXOperators(part)
		for _, lic := range subparts {
			lic = strings.TrimSpace(lic)
			// Remove SPDX expression syntax artifacts
			lic = strings.TrimPrefix(lic, "(")
			lic = strings.TrimSuffix(lic, ")")
			lic = strings.TrimSpace(lic)

			if lic == "" || lic == "OR" || lic == "AND" || lic == "WITH" {
				continue
			}

			// Normalize and deduplicate
			if !seen[lic] {
				seen[lic] = true
				licenses = append(licenses, lic)
			}
		}
	}

	if len(licenses) == 0 {
		return nil
	}
	slices.Sort(licenses)
	return licenses
}

// splitOnSPDXOperators splits a string on SPDX operators (OR, AND) while preserving license identifiers.
func splitOnSPDXOperators(s string) []string {
	var result []string
	// Replace operators with a delimiter we can split on
	s = strings.ReplaceAll(s, " OR ", "\x00")
	s = strings.ReplaceAll(s, " AND ", "\x00")
	s = strings.ReplaceAll(s, " or ", "\x00")
	s = strings.ReplaceAll(s, " and ", "\x00")
	for _, part := range strings.Split(s, "\x00") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// resolveGitHubActionLicense resolves license information for a GitHub Action.
// It handles various version formats including tags, branches, and SHA commits.
func resolveGitHubActionLicense(ctx context.Context, name, version string) []string {
	if name == "" {
		return nil
	}

	// Normalize version - for SHA-pinned versions or branch refs,
	// we should try the default branch instead
	normalizedVersion := normalizeGitHubActionVersion(version)

	// First try with the specified/normalized version
	if lics := license.LookupLicensesBestEffort(ctx, "githubactions", name, normalizedVersion); len(lics) > 0 {
		return lics
	}

	// If that didn't work and we have a SHA or unusual version, try with empty version
	// (which triggers default branch lookup)
	if normalizedVersion != version || looksLikeSHA(version) {
		if lics := license.LookupLicensesBestEffort(ctx, "githubactions", name, ""); len(lics) > 0 {
			return lics
		}
	}

	return nil
}

// normalizeGitHubActionVersion converts various version formats to something
// more likely to resolve successfully.
func normalizeGitHubActionVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return ""
	}

	// If it looks like a full SHA (40 hex chars), we can't use it as a tag
	// Return empty to trigger default branch lookup
	if looksLikeSHA(version) {
		return ""
	}

	// If it's a short SHA-like string (7+ hex chars, no dots), also use default
	if looksLikeShortSHA(version) {
		return ""
	}

	// Normal version tags (v1, v2.0.0, etc.) should work as-is
	return version
}

// looksLikeSHA returns true if the string looks like a full git SHA (40 hex chars).
func looksLikeSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// looksLikeShortSHA returns true if the string looks like a short git SHA
// (7+ hex chars with no dots or other version-like characters).
func looksLikeShortSHA(s string) bool {
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	// If it contains dots, it's probably a version
	if strings.Contains(s, ".") {
		return false
	}
	// If it starts with 'v' followed by a digit, it's a version tag
	if len(s) > 1 && (s[0] == 'v' || s[0] == 'V') && s[1] >= '0' && s[1] <= '9' {
		return false
	}
	// Check if all characters are hex
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
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

// shouldSkipUnresolvable returns true if a package should be excluded from
// the inventory because it cannot be reliably resolved to license information.
// This includes:
// - Container images with variable placeholders (${...})
// - Container images that are internal build artifacts (not public)
// - GitHub Actions from private/internal repositories
func shouldSkipUnresolvable(ecosystem, name, version string) bool {
	switch ecosystem {
	case "container":
		return isUnresolvableContainerImage(name)
	case "githubactions":
		return isUnresolvableGitHubAction(name)
	}
	return false
}

// isUnresolvableContainerImage returns true for container images that cannot
// be resolved to license information.
func isUnresolvableContainerImage(name string) bool {
	// Skip variable placeholders like ${SOURCE_IMAGE}, ${BOSS_PROXY_IMAGE}
	if strings.Contains(name, "${") || strings.Contains(name, "${{") {
		return true
	}

	// Skip ARG references that weren't expanded
	if strings.HasPrefix(name, "${") && strings.HasSuffix(name, "}") {
		return true
	}

	// Normalize the name for checking
	normalized := strings.TrimPrefix(name, "library/")
	normalized = strings.TrimPrefix(normalized, "docker.io/library/")
	normalized = strings.TrimPrefix(normalized, "docker.io/")

	// Skip obvious internal/placeholder images
	// These are patterns commonly used in multi-stage builds as placeholders
	internalPatterns := []string{
		"_image",        // *_image patterns (oss_server_src_image, etc.)
		"-src-image",    // source image placeholders
		"_src_",         // source placeholders
		"builder-fresh", // builder placeholders
	}
	lowerName := strings.ToLower(normalized)
	for _, pattern := range internalPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// isUnresolvableGitHubAction returns true for GitHub Actions that cannot
// be resolved to license information (private repos, internal actions).
func isUnresolvableGitHubAction(name string) bool {
	// Skip actions that reference internal/private repos by common patterns
	// These typically have no public license information

	// Actions with SHA-pinned versions that look like private forks
	// are usually resolvable, so we don't skip those here.
	// The license resolution will handle them.

	return false
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
	return normalizeLicenses(license.RemoteModuleLicenseScan(cctx, module, version))
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
		for _, candidate := range license.DefaultLicenseFilenamesForScan() {
			if strings.HasSuffix(name, strings.ToLower(candidate)) {
				rc, err := f.Open()
				if err != nil {
					continue
				}
				content, _ := io.ReadAll(rc)
				rc.Close()
				out = append(out, license.DetectLicenseIDs(content)...)
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
	tryVersions := crateVersionCandidates(version)
	for _, v := range tryVersions {
		url := fmt.Sprintf("https://crates.io/api/v1/crates/%s/%s", name, v)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		var payload struct {
			Version struct {
				License string `json:"license"`
			} `json:"version"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			resp.Body.Close()
			continue
		}
		resp.Body.Close()
		if l := normalizeLicenses(splitLicenseString(payload.Version.License)); len(l) > 0 {
			return l
		}
	}
	return nil
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

// crateVersionCandidates generates possible semver forms crates.io might accept.
func crateVersionCandidates(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	out := []string{v}
	if strings.HasPrefix(v, "v") {
		out = append(out, strings.TrimPrefix(v, "v"))
	} else {
		out = append(out, "v"+v)
	}
	trimmed := strings.TrimPrefix(v, "v")
	parts := strings.Split(trimmed, ".")
	if len(parts) == 2 {
		out = append(out, trimmed+".0")
		out = append(out, "v"+trimmed+".0")
	}
	if len(parts) == 1 {
		out = append(out, trimmed+".0.0")
		out = append(out, "v"+trimmed+".0.0")
		out = append(out, trimmed+".0")
		out = append(out, "v"+trimmed+".0")
	}
	return normalizeStringSlice(out)
}

func normalizeStringSlice(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
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
