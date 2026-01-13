package license

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	nethttp "net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	pb "deps.dev/api/v3"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/licensecheck"
	"github.com/picatz/deputy/internal/cache/disk"
	"github.com/picatz/deputy/internal/cache/memory"
	"github.com/picatz/deputy/internal/collections"
	"github.com/picatz/deputy/internal/httputil"
	"github.com/picatz/deputy/internal/repository"
	"github.com/picatz/deputy/internal/repository/workspace"
	"golang.org/x/mod/module"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

var defaultLicenseFilenames = []string{
	"LICENSE",
	"LICENSE.txt",
	"LICENSE.md",
	"COPYING",
	"COPYING.txt",
	"COPYRIGHT",
	"UNLICENSE",
}

// Package registry base URLs for license lookups.
// These are variables (not constants) to allow test overrides via WithLicenseEndpoints.
var (
	goProxyBase   = "https://proxy.golang.org"   // Go module proxy
	cratesBase    = "https://crates.io"          // Rust crates registry
	packagistBase = "https://repo.packagist.org" // PHP Composer registry
	pubBase       = "https://pub.dev"            // Dart/Flutter packages
	cocoapodsBase = "https://cocoapods.org"      // iOS/macOS CocoaPods
	hexpmBase     = "https://hex.pm"             // Erlang/Elixir Hex.pm
	pypiBase      = "https://pypi.org"           // Python Package Index
	githubAPIBase = "https://api.github.com"     // GitHub REST API
)

const (
	licenseMemoTTL      = 30 * time.Minute
	licenseMemoMaxItems = 4096
	licenseCacheTTL     = 7 * 24 * time.Hour
	// maxModuleArchiveSize limits the size of module archives (zip, tarball) read
	// into memory when scanning for licenses. This prevents memory exhaustion
	// from unexpectedly large packages.
	maxModuleArchiveSize = 20 << 20 // 20 MB

	// HTTP client timeout constants for license lookups.
	licenseHTTPTimeout = 5 * time.Second  // general license fetches (short, best-effort)
	githubHTTPTimeout  = 10 * time.Second // GitHub API calls (slightly longer for rate limits)
)

// drainAndClose discards remaining response body content and closes the body.
// This is important for HTTP connection reuse - if the body is not fully read,
// the underlying TCP connection cannot be reused for subsequent requests.
func drainAndClose(resp *nethttp.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

// fetchJSON performs an HTTP GET request and decodes the JSON response into v.
// It handles common patterns: context cancellation, non-200 responses, and proper
// connection cleanup. Returns an error if the request fails or response is not 200 OK.
// Optional headers can be passed to set custom request headers (e.g., Accept header).
// Pass nil for headers if no custom headers are needed.
func fetchJSON(ctx context.Context, url string, headers map[string]string, v any) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := licenseHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer drainAndClose(resp)
	if resp.StatusCode != nethttp.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	return nil
}

// DefaultLicenseFilenamesForScan returns the default filenames used when scanning for licenses.
func DefaultLicenseFilenamesForScan() []string {
	return defaultLicenseFilenames
}

// systemFromEcosystem maps a free-form ecosystem string to a deps.dev system.
func systemFromEcosystem(ecosystem string) pb.System {
	switch collections.NormalizeLower(ecosystem) {
	case "go", "golang":
		return pb.System_GO
	case "npm", "javascript", "node", "nodejs":
		return pb.System_NPM
	case "cargo", "rust", "crates", "crates.io":
		return pb.System_CARGO
	case "maven", "java":
		return pb.System_MAVEN
	case "pypi", "python":
		return pb.System_PYPI
	case "nuget", "dotnet", ".net":
		return pb.System_NUGET
	case "rubygems", "ruby", "gem":
		return pb.System_RUBYGEMS
	default:
		return pb.System_SYSTEM_UNSPECIFIED
	}
}

// normalizeVersionForSystem applies ecosystem-specific version normalization.
func normalizeVersionForSystem(system pb.System, version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return ""
	}
	if system == pb.System_GO && !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

// normalizeNameForSystem applies ecosystem-specific normalization to names.
func normalizeNameForSystem(system pb.System, name string) string {
	n := strings.TrimSpace(name)
	if n == "" {
		return ""
	}
	switch system {
	case pb.System_PYPI:
		return strings.ToLower(n)
	default:
		return n
	}
}

// DepsClient abstracts deps.dev client method GetVersion.
type DepsClient interface {
	GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.Version, error)
}

// Resolver looks up license information for packages across ecosystems.
// Implementations handle ecosystem-specific registry APIs and caching.
type Resolver interface {
	// Resolve returns SPDX license identifiers for the given package.
	// Returns nil if no licenses could be determined.
	Resolve(ctx context.Context, ecosystem, name, version string) []string
}

// DefaultResolver returns a Resolver that uses ecosystem-specific registry
// lookups with caching. Pass nil for config to use defaults.
func DefaultResolver(cfg *ResolverConfig) Resolver {
	if cfg == nil {
		cfg = &ResolverConfig{}
	}
	return &registryResolver{cfg: *cfg}
}

// ResolverConfig configures the default license resolver.
type ResolverConfig struct {
	// DepsClient is used for deps.dev license lookups.
	// If nil, deps.dev lookups are skipped.
	DepsClient DepsClient
}

// registryResolver implements Resolver using ecosystem-specific registry APIs.
type registryResolver struct {
	cfg ResolverConfig
}

// Resolve implements Resolver by delegating to LookupLicensesBestEffort.
func (r *registryResolver) Resolve(ctx context.Context, ecosystem, name, version string) []string {
	return LookupLicensesBestEffort(ctx, ecosystem, name, version)
}

// FetchLicensesForPackage queries deps.dev for license info for a module name@version.
// Returns ["?"] on error or missing data to preserve existing UX.
func FetchLicensesForPackage(ctx context.Context, client DepsClient, name, version string) []string {
	return FetchLicensesForEcosystem(ctx, client, "go", name, version)
}

// FetchLicensesForEcosystem queries deps.dev for license info for a package in the
// given ecosystem. Returns ["?"] on error or missing data to preserve existing UX.
func FetchLicensesForEcosystem(ctx context.Context, client DepsClient, ecosystem, name, version string) []string {
	if version == "" || name == "" {
		return []string{"?"}
	}
	system := systemFromEcosystem(ecosystem)
	if system == pb.System_SYSTEM_UNSPECIFIED {
		return []string{"?"}
	}
	v := normalizeVersionForSystem(system, version)
	n := normalizeNameForSystem(system, name)
	key := fmt.Sprintf("%d|%s@%s", system, n, v)
	var cached []string
	if disk.Read("depsdev", key, licenseCacheTTL, &cached) && len(cached) > 0 {
		return cached
	}
	if client == nil {
		return []string{"?"}
	}
	raw, err := client.GetVersion(ctx, &pb.GetVersionRequest{VersionKey: &pb.VersionKey{System: system, Name: n, Version: v}})
	if err != nil || raw == nil || len(raw.Licenses) == 0 {
		return []string{"?"}
	}
	disk.Write("depsdev", key, raw.Licenses)
	return raw.Licenses
}

// LocalRepoLicenseScan inspects a workspace-backed repository (depth-limited)
// for license-looking files and returns detected SPDX identifiers (best effort).
// Hidden directories (like .git) are skipped and the traversal stays shallow
// to keep performance bounded regardless of backend storage.
func LocalRepoLicenseScan(ws workspace.FS) []string {
	if ws == nil {
		return nil
	}
	const maxSeparatorCount = 2
	var candidates []string
	for _, name := range defaultLicenseFilenames {
		if fi, err := ws.Stat(name); err == nil && !fi.IsDir() {
			candidates = append(candidates, name)
		}
	}
	stack := []string{"."}
	for len(stack) > 0 {
		idx := len(stack) - 1
		current := stack[idx]
		stack = stack[:idx]
		entries, err := ws.ReadDir(current)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			rel := name
			if current != "." {
				rel = filepath.Join(current, name)
			}
			if entry.IsDir() {
				if strings.HasPrefix(name, ".") && name != "." {
					continue
				}
				if strings.Count(rel, string(os.PathSeparator)) > maxSeparatorCount {
					continue
				}
				stack = append(stack, rel)
				continue
			}
			if strings.Count(rel, string(os.PathSeparator)) > maxSeparatorCount {
				continue
			}
			lower := strings.ToLower(name)
			if strings.HasPrefix(lower, "license") || strings.HasPrefix(lower, "copying") || lower == "copyright" || lower == "unlicense" || strings.HasPrefix(lower, "licence") {
				candidates = append(candidates, rel)
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}

	// Use bounded concurrency to prevent resource exhaustion when scanning
	// many license files. The limit of 10 is chosen to balance parallelism
	// with resource usage.
	const maxConcurrentScans = 10

	type res struct{ id string }
	ch := make(chan res, len(candidates))

	g := new(errgroup.Group)
	g.SetLimit(maxConcurrentScans)

	for _, f := range candidates {
		f := f
		g.Go(func() error {
			data, err := ws.ReadFile(f)
			if err != nil {
				return nil // Ignore read errors, continue with other files
			}
			for _, id := range DetectLicenseIDs(data) {
				if id != "" {
					ch <- res{id: id}
				}
			}
			return nil
		})
	}

	// Close channel after all goroutines complete
	go func() {
		g.Wait()
		close(ch)
	}()

	seen := collections.NewSet[string]()
	var out []string
	for r := range ch {
		if !seen.Add(r.id) {
			continue
		}
		out = append(out, r.id)
	}
	slices.Sort(out)
	return out
}

// License lookup caching and request deduplication.
//
// We use a two-layer caching strategy with singleflight for request coalescing:
//
//  1. TTL cache (remoteLicenseMemo, registryLicenseMemo): In-memory cache with
//     time-based expiration for quick repeated lookups within a session.
//
//  2. Singleflight groups (remoteLicenseGroup, registryLicenseGroup): Prevent
//     duplicate in-flight requests for the same key. When multiple goroutines
//     request the same license info concurrently, only one HTTP request is made
//     and all waiters receive the same result.
//
// This pattern is especially important during SBOM generation and vulnerability
// scanning where the same package may be referenced multiple times.
var (
	remoteLicenseMemo    = memory.NewTTLCache[string, []string](licenseMemoMaxItems, licenseMemoTTL)
	remoteLicenseGroup   singleflight.Group
	registryLicenseMemo  = memory.NewTTLCache[string, []string](licenseMemoMaxItems, licenseMemoTTL)
	registryLicenseGroup singleflight.Group
	githubHTTPClientOnce sync.Once
	githubHTTPClient     *nethttp.Client
	// licenseHTTPClient uses retryable HTTP with SSRF protection for resilience
	// against transient failures when fetching license data from package registries
	// (crates.io, packagist, etc.). SafeDialer prevents DNS rebinding attacks.
	licenseHTTPClient = httputil.NewSafeRetryableClient(licenseHTTPTimeout)
)

// MergeLicenseSources merges deps.dev licenses (primary) with locally scanned
// ones (secondary). Returns '?' if both empty. Removes duplicates.
func MergeLicenseSources(primary, local []string) []string {
	set := collections.NewSet[string]()
	for _, s := range primary {
		if s != "" && s != "?" {
			set.Add(s)
		}
	}
	for _, s := range local {
		if s != "" && s != "?" {
			set.Add(s)
		}
	}
	if len(set) == 0 {
		return []string{"?"}
	}
	out := set.Slice()
	slices.Sort(out)
	return out
}

// DetectLicenseIDs scans raw license text bytes and returns unique SPDX style IDs.
func DetectLicenseIDs(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	cov := licensecheck.Scan(b)
	if len(cov.Match) == 0 {
		return nil
	}
	seen := collections.NewSet[string]()
	var out []string
	for _, m := range cov.Match {
		id := m.ID
		if id == "" {
			continue
		}
		if !seen.Add(id) {
			continue
		}
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// RemoteModuleLicenseScan performs a best-effort license scan for a remote module.
// It supports GitHub-hosted modules via raw fetch/clone and falls back to scanning
// the Go module proxy zip when possible.
func RemoteModuleLicenseScan(ctx context.Context, modulePath, version string) []string {
	if modulePath == "" {
		return nil
	}
	key := modulePath + "@" + version
	if cached, ok := remoteLicenseMemo.Get(key); ok {
		return slices.Clone(cached)
	}
	var diskCached []string
	if version != "" && disk.Read("license-scan", key, licenseCacheTTL, &diskCached) && len(diskCached) > 0 {
		remoteLicenseMemo.Set(key, slices.Clone(diskCached))
		return slices.Clone(diskCached)
	}
	result, _, _ := remoteLicenseGroup.Do(key, func() (any, error) {
		if cached, ok := remoteLicenseMemo.Get(key); ok {
			return slices.Clone(cached), nil
		}
		if version != "" && len(diskCached) > 0 {
			return slices.Clone(diskCached), nil
		}
		var ids []string
		if strings.HasPrefix(modulePath, "github.com/") {
			if parts := strings.Split(modulePath, "/"); len(parts) >= 3 {
				// Try GitHub License API first (single fast request with SPDX ID)
				if apiIDs := fetchLicenseFromGitHubAPI(ctx, parts[1], parts[2]); len(apiIDs) > 0 {
					ids = apiIDs
				} else if rawIDs, err := fetchLicensesFromGitHubRaw(ctx, parts[1], parts[2], version); err == nil && len(rawIDs) > 0 {
					ids = rawIDs
				} else {
					repoURL := fmt.Sprintf("https://github.com/%s/%s.git", parts[1], parts[2])
					opts := &git.CloneOptions{URL: repoURL, Depth: 1, SingleBranch: true, Tags: git.NoTags}
					if version != "" {
						v := version
						if !strings.HasPrefix(v, "v") {
							v = "v" + v
						}
						opts.ReferenceName = plumbing.ReferenceName("refs/tags/" + v)
					}
					if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
						opts.Auth = &githttp.BasicAuth{Username: "oauth2", Password: tok}
					}
					if src, err := repository.CloneInMemory(ctx, opts); err == nil {
						defer src.Close()
						ids = LocalRepoLicenseScan(src.Workspace())
					}
				}
			}
		}
		if len(ids) == 0 && version != "" {
			if gp := GoProxyLicenseScan(ctx, modulePath, version); len(gp) > 0 {
				ids = gp
			}
		}
		if version != "" && len(ids) > 0 {
			disk.Write("license-scan", key, ids)
		}
		remoteLicenseMemo.Set(key, slices.Clone(ids))
		return ids, nil
	})
	if ids, ok := result.([]string); ok {
		return slices.Clone(ids)
	}
	return nil
}

// LookupLicensesBestEffort queries ecosystem-specific registries or content to
// populate licenses when upstream metadata is missing. It leverages registry APIs
// (Go proxy zips, crates.io, Packagist) in addition to GitHub raw/clone scans.
func LookupLicensesBestEffort(ctx context.Context, ecosystem, name, version string) []string {
	eco := collections.NormalizeLower(ecosystem)
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if eco == "" || name == "" {
		return nil
	}

	// Check well-known licenses first (no network, instant lookup).
	// This handles Go stdlib, toolchain, and common packages with known licenses.
	if lics := wellKnownLicense(eco, name, version); len(lics) > 0 {
		return lics
	}

	// Version is required for most registry lookups, but GitHub-based ecosystems
	// can use the GitHub License API without a version (returns default branch license).
	isGitHubBased := eco == "github" || eco == "github actions" || eco == "github-actions" ||
		eco == "githubactions" || eco == "gha" ||
		(eco == "go" || eco == "golang") && strings.HasPrefix(name, "github.com/")
	if version == "" && !isGitHubBased {
		return nil
	}

	key := eco + "|" + name + "@" + version
	if cached, ok := registryLicenseMemo.Get(key); ok {
		return slices.Clone(cached)
	}
	var diskCached []string
	if disk.Read("license-registry", key, licenseCacheTTL, &diskCached) && len(diskCached) > 0 {
		registryLicenseMemo.Set(key, slices.Clone(diskCached))
		return slices.Clone(diskCached)
	}
	result, _, _ := registryLicenseGroup.Do(key, func() (any, error) {
		if cached, ok := registryLicenseMemo.Get(key); ok {
			return slices.Clone(cached), nil
		}
		lics := resolveEcosystemLicenses(ctx, eco, name, version)
		if len(lics) > 0 {
			disk.Write("license-registry", key, lics)
		}
		registryLicenseMemo.Set(key, slices.Clone(lics))
		return lics, nil
	})
	if lics, ok := result.([]string); ok {
		return slices.Clone(lics)
	}
	return nil
}

// wellKnownLicense returns hardcoded licenses for packages that don't have
// license metadata in any registry. This is a minimal list of truly essential
// cases where network lookups will never succeed.
//
// Sources:
//   - Go stdlib/toolchain: https://go.dev/LICENSE (BSD-3-Clause)
func wellKnownLicense(ecosystem, name, version string) []string {
	switch ecosystem {
	case "go", "golang":
		// Go standard library and toolchain - not published to any registry
		nameLower := strings.ToLower(name)
		if nameLower == "stdlib" || nameLower == "go" || nameLower == "toolchain" {
			return []string{"BSD-3-Clause"}
		}
	}
	return nil
}

func resolveEcosystemLicenses(ctx context.Context, ecosystem, name, version string) []string {
	switch ecosystem {
	case "go", "golang":
		return mergeLicenseSets(
			RemoteModuleLicenseScan(ctx, name, version),
			GoProxyLicenseScan(ctx, name, version),
		)
	case "github", "github actions", "github-actions", "githubactions", "gha":
		repo := name
		if !strings.HasPrefix(repo, "github.com/") {
			repo = "github.com/" + strings.TrimPrefix(repo, "/")
		}
		return RemoteModuleLicenseScan(ctx, repo, version)
	case "cargo", "rust", "crates", "crates.io":
		return LookupCratesLicense(ctx, name, version)
	case "pypi", "python":
		return LookupPyPILicense(ctx, name, version)
	case "php", "composer", "packagist":
		return LookupPackagistLicense(ctx, name, version)
	case "dart", "pub":
		return LookupPubLicense(ctx, name, version)
	case "cocoapods", "pod", "pods":
		return LookupCocoaPodsLicense(ctx, name, version)
	case "hex":
		return LookupHexLicense(ctx, name, version)
	default:
		return RemoteModuleLicenseScan(ctx, name, version)
	}
}

// GoProxyLicenseScan downloads the module zip from proxy.golang.org and scans
// license-looking files for SPDX identifiers.
func GoProxyLicenseScan(ctx context.Context, modulePath, version string) []string {
	modulePath = strings.TrimSpace(modulePath)
	version = strings.TrimSpace(version)
	if modulePath == "" || version == "" || ctx.Err() != nil {
		return nil
	}
	encPath, err := module.EscapePath(modulePath)
	if err != nil {
		return nil
	}
	url := fmt.Sprintf("%s/%s/@v/%s.zip", strings.TrimRight(goProxyBase, "/"), encPath, version)
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := licenseHTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer drainAndClose(resp)
	if resp.StatusCode != nethttp.StatusOK {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxModuleArchiveSize))
	if err != nil || len(data) == 0 {
		return nil
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	var ids []string
	for _, f := range zr.File {
		lower := strings.ToLower(f.Name)
		for _, candidate := range defaultLicenseFilenames {
			if strings.HasSuffix(lower, strings.ToLower(candidate)) {
				rc, err := f.Open()
				if err != nil {
					continue
				}
				content, _ := io.ReadAll(rc)
				rc.Close()
				ids = append(ids, DetectLicenseIDs(content)...)
			}
		}
	}
	return cleanLicenseList(ids)
}

// LookupPyPILicense queries PyPI's JSON API for license metadata.
// It checks both the license_expression field (SPDX, preferred) and classifiers.
// See: https://docs.pypi.org/api/json/
func LookupPyPILicense(ctx context.Context, name, version string) []string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" || ctx.Err() != nil {
		return nil
	}
	// PyPI package names are case-insensitive and normalize - to _
	normalizedName := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	url := fmt.Sprintf("%s/pypi/%s/%s/json", pypiBase, normalizedName, version)
	var payload struct {
		Info struct {
			License           string   `json:"license"`
			LicenseExpression string   `json:"license_expression"`
			Classifiers       []string `json:"classifiers"`
		} `json:"info"`
	}
	if err := fetchJSON(ctx, url, nil, &payload); err != nil {
		return nil
	}
	// Prefer license_expression (SPDX standard per PEP 639)
	if expr := strings.TrimSpace(payload.Info.LicenseExpression); expr != "" {
		return cleanLicenseList(splitLicenseString(expr))
	}
	// Fall back to license field if it looks like an SPDX identifier
	if lic := strings.TrimSpace(payload.Info.License); lic != "" && looksLikeSPDX(lic) {
		return cleanLicenseList(splitLicenseString(lic))
	}
	// Extract from classifiers as last resort
	for _, c := range payload.Info.Classifiers {
		if strings.HasPrefix(c, "License :: OSI Approved :: ") {
			if spdx := classifierToSPDX(c); spdx != "" {
				return []string{spdx}
			}
		}
	}
	return nil
}

// looksLikeSPDX returns true if the string looks like an SPDX identifier
// rather than free-form license text.
func looksLikeSPDX(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 100 {
		return false
	}
	// SPDX identifiers don't have newlines or lots of spaces
	if strings.Contains(s, "\n") || strings.Count(s, " ") > 5 {
		return false
	}
	// Common SPDX patterns
	spdxPatterns := []string{"MIT", "Apache", "BSD", "GPL", "LGPL", "MPL", "ISC", "Zlib", "PSF", "Unlicense"}
	sUpper := strings.ToUpper(s)
	for _, p := range spdxPatterns {
		if strings.Contains(sUpper, strings.ToUpper(p)) {
			return true
		}
	}
	return false
}

// classifierToSPDX maps PyPI license classifiers to SPDX identifiers.
func classifierToSPDX(classifier string) string {
	// Map common classifiers to SPDX
	mapping := map[string]string{
		"License :: OSI Approved :: MIT License":                                    "MIT",
		"License :: OSI Approved :: Apache Software License":                        "Apache-2.0",
		"License :: OSI Approved :: BSD License":                                    "BSD-3-Clause",
		"License :: OSI Approved :: GNU General Public License v2 (GPLv2)":          "GPL-2.0-only",
		"License :: OSI Approved :: GNU General Public License v3 (GPLv3)":          "GPL-3.0-only",
		"License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)":  "LGPL-2.0-only",
		"License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)":  "LGPL-3.0-only",
		"License :: OSI Approved :: ISC License (ISCL)":                             "ISC",
		"License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)":           "MPL-2.0",
		"License :: OSI Approved :: Python Software Foundation License":             "PSF-2.0",
		"License :: OSI Approved :: The Unlicense (Unlicense)":                      "Unlicense",
		"License :: OSI Approved :: zlib/libpng License":                            "Zlib",
		"License :: Public Domain":                                                  "CC0-1.0",
		"License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication":           "CC0-1.0",
	}
	if spdx, ok := mapping[classifier]; ok {
		return spdx
	}
	return ""
}

// LookupCratesLicense queries crates.io for license metadata.
func LookupCratesLicense(ctx context.Context, name, version string) []string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" || ctx.Err() != nil {
		return nil
	}
	for _, v := range crateVersionCandidates(version) {
		url := fmt.Sprintf("%s/api/v1/crates/%s/%s", strings.TrimRight(cratesBase, "/"), name, v)
		req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := licenseHTTPClient.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != nethttp.StatusOK {
			drainAndClose(resp)
			continue
		}
		var payload struct {
			Version struct {
				License string `json:"license"`
			} `json:"version"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			drainAndClose(resp)
			continue
		}
		drainAndClose(resp)
		if l := cleanLicenseList(splitLicenseString(payload.Version.License)); len(l) > 0 {
			return l
		}
	}
	return nil
}

// LookupPackagistLicense queries packagist.org for license metadata.
func LookupPackagistLicense(ctx context.Context, name, version string) []string {
	name = collections.NormalizeLower(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" || ctx.Err() != nil {
		return nil
	}
	if l := lookupPackagistP2(ctx, name, version); len(l) > 0 {
		return l
	}
	return lookupPackagistLegacy(ctx, name, version)
}

func lookupPackagistP2(ctx context.Context, name, version string) []string {
	url := fmt.Sprintf("%s/p2/%s.json", strings.TrimRight(packagistBase, "/"), name)
	var payload struct {
		Packages map[string][]struct {
			Version           string   `json:"version"`
			VersionNormalized string   `json:"version_normalized"`
			License           []string `json:"license"`
		} `json:"packages"`
	}
	if err := fetchJSON(ctx, url, nil, &payload); err != nil {
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
	for _, v := range packagistVersionCandidates(version) {
		for _, pkg := range versions {
			if pkg.Version == v || pkg.VersionNormalized == v {
				if l := cleanLicenseList(pkg.License); len(l) > 0 {
					return l
				}
			}
		}
	}
	for _, pkg := range versions {
		if l := cleanLicenseList(pkg.License); len(l) > 0 {
			return l
		}
	}
	return nil
}

func lookupPackagistLegacy(ctx context.Context, name, version string) []string {
	url := fmt.Sprintf("%s/p/%s.json", strings.TrimRight(packagistBase, "/"), name)
	var payload struct {
		Packages map[string]map[string]struct {
			License           []string `json:"license"`
			VersionNormalized string   `json:"version_normalized"`
		} `json:"packages"`
	}
	if err := fetchJSON(ctx, url, nil, &payload); err != nil {
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
	for _, v := range packagistVersionCandidates(version) {
		if pkg, ok := versions[v]; ok {
			if l := cleanLicenseList(pkg.License); len(l) > 0 {
				return l
			}
		}
	}
	for _, pkg := range versions {
		if l := cleanLicenseList(pkg.License); len(l) > 0 {
			return l
		}
	}
	return nil
}

func packagistVersionCandidates(version string) []string {
	v := strings.TrimSpace(version)
	if v == "" {
		return nil
	}
	out := []string{v}
	if strings.HasPrefix(v, "v") {
		out = append(out, strings.TrimPrefix(v, "v"))
	} else {
		out = append(out, "v"+v)
	}
	return normalizeStringSlice(out)
}

// LookupPubLicense fetches license metadata from pub.dev package API.
func LookupPubLicense(ctx context.Context, name, version string) []string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return nil
	}
	url := fmt.Sprintf("%s/api/packages/%s/versions/%s", strings.TrimRight(pubBase, "/"), name, version)
	var payload struct {
		ArchiveURL string `json:"archive_url"`
		Pubspec    struct {
			License string `json:"license"`
		} `json:"pubspec"`
	}
	if err := fetchJSON(ctx, url, nil, &payload); err != nil {
		return nil
	}
	if lic := cleanLicenseList(splitLicenseString(payload.Pubspec.License)); len(lic) > 0 {
		return lic
	}
	if payload.ArchiveURL == "" {
		return nil
	}
	return scanTarballForLicenses(ctx, payload.ArchiveURL)
}

// LookupCocoaPodsLicense fetches license metadata from the CocoaPods API.
func LookupCocoaPodsLicense(ctx context.Context, name, version string) []string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return nil
	}
	// First, get the data URL from the version endpoint
	url := fmt.Sprintf("https://trunk.cocoapods.org/api/v1/pods/%s/versions/%s", name, version)
	var payload struct {
		DataURL string `json:"data_url"`
	}
	if err := fetchJSON(ctx, url, map[string]string{"Accept": "application/json"}, &payload); err != nil {
		return nil
	}
	if payload.DataURL == "" {
		return nil
	}
	// Then fetch the podspec from the data URL
	var podspec map[string]any
	if err := fetchJSON(ctx, payload.DataURL, nil, &podspec); err != nil {
		return nil
	}
	return extractCocoaPodsLicense(podspec)
}

// extractCocoaPodsLicense extracts license information from a CocoaPods podspec.
func extractCocoaPodsLicense(podspec map[string]any) []string {
	licVal, ok := podspec["license"]
	if !ok {
		licVal = podspec["licenses"]
	}
	switch v := licVal.(type) {
	case string:
		return cleanLicenseList(splitLicenseString(v))
	case map[string]any:
		if t, ok := v["type"].(string); ok {
			return cleanLicenseList([]string{t})
		}
		if s, ok := v["text"].(string); ok {
			return cleanLicenseList(splitLicenseString(s))
		}
	case []any:
		var parts []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				parts = append(parts, s)
			}
		}
		if len(parts) > 0 {
			return cleanLicenseList(parts)
		}
	}
	return nil
}

// LookupHexLicense fetches license metadata from hex.pm API.
func LookupHexLicense(ctx context.Context, name, version string) []string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return nil
	}
	url := fmt.Sprintf("%s/api/packages/%s", strings.TrimRight(hexpmBase, "/"), name)
	var payload struct {
		Meta struct {
			Licenses []string `json:"licenses"`
		} `json:"meta"`
	}
	if err := fetchJSON(ctx, url, nil, &payload); err != nil {
		return nil
	}
	return cleanLicenseList(payload.Meta.Licenses)
}

func scanTarballForLicenses(ctx context.Context, url string) []string {
	if ctx.Err() != nil || url == "" {
		return nil
	}
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := licenseHTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer drainAndClose(resp)
	if resp.StatusCode != nethttp.StatusOK {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxModuleArchiveSize))
	if err != nil || len(data) == 0 {
		return nil
	}
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	var ids []string
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		lower := strings.ToLower(filepath.Base(hdr.Name))
		for _, candidate := range defaultLicenseFilenames {
			if strings.ToLower(candidate) == lower || strings.HasSuffix(lower, strings.ToLower(candidate)) {
				content, _ := io.ReadAll(io.LimitReader(tr, 1<<20))
				ids = append(ids, DetectLicenseIDs(content)...)
			}
		}
	}
	return cleanLicenseList(ids)
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
	seen := collections.NewSet[string]()
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !seen.Add(s) {
			continue
		}
		out = append(out, s)
	}
	return out
}

func cleanLicenseList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := collections.NewSet[string]()
	var out []string
	for _, l := range in {
		l = strings.TrimSpace(l)
		if l == "" || l == "?" {
			continue
		}
		if !seen.Add(l) {
			continue
		}
		out = append(out, l)
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	return out
}

func mergeLicenseSets(groups ...[]string) []string {
	if len(groups) == 0 {
		return nil
	}
	var combined []string
	for _, g := range groups {
		combined = append(combined, g...)
	}
	return cleanLicenseList(combined)
}

// ExtractLicensesFromReader allows tests to exercise detection on arbitrary content.
func ExtractLicensesFromReader(r io.Reader) []string {
	b, _ := io.ReadAll(r)
	return DetectLicenseIDs(b)
}

// getGitHubHTTPClient returns a singleton HTTP client configured with a timeout
// suitable for GitHub API requests. Uses retryable HTTP with SSRF protection
// for resilience against transient failures and rate limiting.
func getGitHubHTTPClient() *nethttp.Client {
	githubHTTPClientOnce.Do(func() {
		githubHTTPClient = httputil.NewSafeRetryableClient(githubHTTPTimeout)
	})
	return githubHTTPClient
}

// fetchLicenseFromGitHubAPI queries the GitHub License API to get the repository's
// detected license. This is the fastest method as it returns the SPDX ID directly
// in a single API call. See: https://docs.github.com/rest/reference/licenses
//
// Returns nil if the API call fails or no license is detected.
func fetchLicenseFromGitHubAPI(ctx context.Context, owner, repo string) []string {
	if owner == "" || repo == "" || ctx.Err() != nil {
		return nil
	}
	client := getGitHubHTTPClient()
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))

	url := fmt.Sprintf("%s/repos/%s/%s/license", githubAPIBase, owner, repo)
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "deputy-license-scan")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer drainAndClose(resp)

	if resp.StatusCode != nethttp.StatusOK {
		return nil
	}

	var payload struct {
		License struct {
			Key    string `json:"key"`
			SPDXID string `json:"spdx_id"`
			Name   string `json:"name"`
		} `json:"license"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}

	// Prefer SPDX ID (e.g., "MIT", "Apache-2.0")
	if spdx := strings.TrimSpace(payload.License.SPDXID); spdx != "" && spdx != "NOASSERTION" {
		return []string{spdx}
	}
	// Fall back to key which is usually lowercase SPDX-like (e.g., "mit", "apache-2.0")
	if key := strings.TrimSpace(payload.License.Key); key != "" && key != "other" {
		return []string{strings.ToUpper(key)}
	}
	return nil
}

// fetchLicensesFromGitHubRaw attempts to download license files directly from
// GitHub's raw content domain. This avoids the overhead of a full git clone
// when only the license text is needed.
//
// License files are fetched in parallel with bounded concurrency to improve
// performance while respecting GitHub rate limits.
func fetchLicensesFromGitHubRaw(ctx context.Context, owner, repo, version string) ([]string, error) {
	ref := deriveGitRef(version)
	if ref == "" {
		return nil, fmt.Errorf("unable to derive git ref")
	}
	client := getGitHubHTTPClient()
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))

	// Fetch all license files in parallel with bounded concurrency.
	// This significantly speeds up license detection since we check 7 filenames.
	const maxConcurrent = 4 // conservative to avoid GitHub rate limits
	type result struct {
		ids []string
	}
	ch := make(chan result, len(defaultLicenseFilenames))

	g := new(errgroup.Group)
	g.SetLimit(maxConcurrent)

	for _, name := range defaultLicenseFilenames {
		name := name // capture loop variable
		g.Go(func() error {
			url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, ref, name)
			req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, url, nil)
			if err != nil {
				return nil // non-fatal, continue with other files
			}
			req.Header.Set("User-Agent", "deputy-license-scan")
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			resp, err := client.Do(req)
			if err != nil {
				return nil // non-fatal
			}
			if resp.StatusCode == nethttp.StatusNotFound {
				drainAndClose(resp)
				return nil
			}
			if resp.StatusCode != nethttp.StatusOK {
				drainAndClose(resp)
				return nil
			}
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || len(data) == 0 {
				return nil
			}
			if ids := DetectLicenseIDs(data); len(ids) > 0 {
				ch <- result{ids: ids}
			}
			return nil
		})
	}

	// Close channel after all goroutines complete
	go func() {
		g.Wait()
		close(ch)
	}()

	// Collect results
	seen := collections.NewSet[string]()
	var out []string
	for r := range ch {
		for _, id := range r.ids {
			if id == "" {
				continue
			}
			if !seen.Add(id) {
				continue
			}
			out = append(out, id)
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no license files via raw")
	}
	slices.Sort(out)
	return out, nil
}

// deriveGitRef attempts to extract a usable git reference (commit hash or tag)
// from a version string. It handles Go pseudo-versions and standard semantic
// versions.
func deriveGitRef(version string) string {
	if version == "" {
		return ""
	}
	v := version
	if idx := strings.Index(v, "+"); idx != -1 {
		v = v[:idx]
	}
	if commit := pseudoVersionCommit(v); commit != "" {
		return commit
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

// pseudoVersionCommit extracts the commit hash from a Go pseudo-version string
// (e.g., v0.0.0-20230101000000-abcdef123456).
func pseudoVersionCommit(version string) string {
	parts := strings.Split(version, "-")
	if len(parts) < 3 {
		return ""
	}
	commit := parts[len(parts)-1]
	if len(commit) < 7 || len(commit) > 40 {
		return ""
	}
	commit = strings.ToLower(commit)
	for _, r := range commit {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return commit
}
