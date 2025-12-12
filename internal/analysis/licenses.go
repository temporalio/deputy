package analysis

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
	"sort"
	"strings"
	"sync"
	"time"

	pb "deps.dev/api/v3"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/licensecheck"
	"github.com/picatz/deputy/internal/repository"
	"github.com/picatz/deputy/internal/repository/workspace"
	"golang.org/x/mod/module"
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

var (
	goProxyBase   = "https://proxy.golang.org"
	cratesBase    = "https://crates.io"
	packagistBase = "https://repo.packagist.org"
	pubBase       = "https://pub.dev"
	cocoapodsBase = "https://cocoapods.org"
	hexpmBase     = "https://hex.pm"
)

// DefaultLicenseFilenamesForScan returns the default filenames used when scanning for licenses.
func DefaultLicenseFilenamesForScan() []string {
	return defaultLicenseFilenames
}

// systemFromEcosystem maps a free-form ecosystem string to a deps.dev system.
func systemFromEcosystem(ecosystem string) pb.System {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
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
	if readCache("depsdev", key, &cached) && len(cached) > 0 {
		return cached
	}
	if client == nil {
		return []string{"?"}
	}
	raw, err := client.GetVersion(ctx, &pb.GetVersionRequest{VersionKey: &pb.VersionKey{System: system, Name: n, Version: v}})
	if err != nil || raw == nil || len(raw.Licenses) == 0 {
		return []string{"?"}
	}
	writeCache("depsdev", key, raw.Licenses)
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
	type res struct{ id string }
	ch := make(chan res, len(candidates))
	var wg sync.WaitGroup
	for _, f := range candidates {
		f := f
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := ws.ReadFile(f)
			if err != nil {
				return
			}
			for _, id := range DetectLicenseIDs(data) {
				if id != "" {
					ch <- res{id: id}
				}
			}
		}()
	}
	wg.Wait()
	close(ch)
	seen := map[string]struct{}{}
	var out []string
	for r := range ch {
		if _, ok := seen[r.id]; ok {
			continue
		}
		seen[r.id] = struct{}{}
		out = append(out, r.id)
	}
	sort.Strings(out)
	return out
}

var (
	remoteLicenseMemo    sync.Map // string -> []string
	remoteLicenseGroup   singleflight.Group
	registryLicenseMemo  sync.Map // string -> []string (ecosystem-aware)
	registryLicenseGroup singleflight.Group
	githubHTTPClientOnce sync.Once
	githubHTTPClient     *nethttp.Client
	licenseHTTPClient    = &nethttp.Client{Timeout: 5 * time.Second}
)

// MergeLicenseSources merges deps.dev licenses (primary) with locally scanned
// ones (secondary). Returns '?' if both empty. Removes duplicates.
func MergeLicenseSources(primary, local []string) []string {
	set := map[string]struct{}{}
	for _, s := range primary {
		if s != "" && s != "?" {
			set[s] = struct{}{}
		}
	}
	for _, s := range local {
		if s != "" && s != "?" {
			set[s] = struct{}{}
		}
	}
	if len(set) == 0 {
		return []string{"?"}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
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
	seen := map[string]struct{}{}
	var out []string
	for _, m := range cov.Match {
		id := m.ID
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
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
	if cached, ok := remoteLicenseMemo.Load(key); ok {
		return cloneStrings(cached.([]string))
	}
	var diskCached []string
	if version != "" && readCache("license-scan", key, &diskCached) && len(diskCached) > 0 {
		remoteLicenseMemo.Store(key, cloneStrings(diskCached))
		return cloneStrings(diskCached)
	}
	result, _, _ := remoteLicenseGroup.Do(key, func() (interface{}, error) {
		if cached, ok := remoteLicenseMemo.Load(key); ok {
			return cloneStrings(cached.([]string)), nil
		}
		if version != "" && len(diskCached) > 0 {
			return cloneStrings(diskCached), nil
		}
		var ids []string
		if strings.HasPrefix(modulePath, "github.com/") {
			if parts := strings.Split(modulePath, "/"); len(parts) >= 3 {
				if rawIDs, err := fetchLicensesFromGitHubRaw(ctx, parts[1], parts[2], version); err == nil && len(rawIDs) > 0 {
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
						ids = LocalRepoLicenseScan(src.Workspace)
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
			writeCache("license-scan", key, ids)
		}
		remoteLicenseMemo.Store(key, cloneStrings(ids))
		return ids, nil
	})
	if ids, ok := result.([]string); ok {
		return cloneStrings(ids)
	}
	return nil
}

// LookupLicensesBestEffort queries ecosystem-specific registries or content to
// populate licenses when upstream metadata is missing. It leverages registry APIs
// (Go proxy zips, crates.io, Packagist) in addition to GitHub raw/clone scans.
func LookupLicensesBestEffort(ctx context.Context, ecosystem, name, version string) []string {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if eco == "" || name == "" || version == "" {
		return nil
	}
	key := eco + "|" + name + "@" + version
	if cached, ok := registryLicenseMemo.Load(key); ok {
		return cloneStrings(cached.([]string))
	}
	var diskCached []string
	if readCache("license-registry", key, &diskCached) && len(diskCached) > 0 {
		registryLicenseMemo.Store(key, cloneStrings(diskCached))
		return cloneStrings(diskCached)
	}
	result, _, _ := registryLicenseGroup.Do(key, func() (interface{}, error) {
		if cached, ok := registryLicenseMemo.Load(key); ok {
			return cloneStrings(cached.([]string)), nil
		}
		lics := resolveEcosystemLicenses(ctx, eco, name, version)
		if len(lics) > 0 {
			writeCache("license-registry", key, lics)
		}
		registryLicenseMemo.Store(key, cloneStrings(lics))
		return lics, nil
	})
	if lics, ok := result.([]string); ok {
		return cloneStrings(lics)
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
	defer resp.Body.Close()
	if resp.StatusCode != nethttp.StatusOK {
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
		if l := cleanLicenseList(splitLicenseString(payload.Version.License)); len(l) > 0 {
			return l
		}
	}
	return nil
}

// LookupPackagistLicense queries packagist.org for license metadata.
func LookupPackagistLicense(ctx context.Context, name, version string) []string {
	name = strings.ToLower(strings.TrimSpace(name))
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
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := licenseHTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != nethttp.StatusOK {
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
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := licenseHTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != nethttp.StatusOK {
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
	if name == "" || version == "" || ctx.Err() != nil {
		return nil
	}
	url := fmt.Sprintf("%s/api/packages/%s/versions/%s", strings.TrimRight(pubBase, "/"), name, version)
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := licenseHTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != nethttp.StatusOK {
		return nil
	}
	var payload struct {
		ArchiveURL string `json:"archive_url"`
		Pubspec    struct {
			License string `json:"license"`
		} `json:"pubspec"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
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
	if name == "" || version == "" || ctx.Err() != nil {
		return nil
	}
	url := fmt.Sprintf("https://trunk.cocoapods.org/api/v1/pods/%s/versions/%s", name, version)
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	resp, err := licenseHTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != nethttp.StatusOK {
		return nil
	}
	var payload struct {
		DataURL string `json:"data_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}
	if payload.DataURL == "" {
		return nil
	}
	reqSpec, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, payload.DataURL, nil)
	if err != nil {
		return nil
	}
	respSpec, err := licenseHTTPClient.Do(reqSpec)
	if err != nil {
		return nil
	}
	defer respSpec.Body.Close()
	if respSpec.StatusCode != nethttp.StatusOK {
		return nil
	}
	var podspec map[string]any
	if err := json.NewDecoder(respSpec.Body).Decode(&podspec); err != nil {
		return nil
	}
	licVal, ok := podspec["license"]
	if !ok {
		licVal, ok = podspec["licenses"]
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
	if name == "" || version == "" || ctx.Err() != nil {
		return nil
	}
	url := fmt.Sprintf("%s/api/packages/%s", strings.TrimRight(hexpmBase, "/"), name)
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := licenseHTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != nethttp.StatusOK {
		return nil
	}
	var payload struct {
		Meta struct {
			Licenses []string `json:"licenses"`
		} `json:"meta"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
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
	defer resp.Body.Close()
	if resp.StatusCode != nethttp.StatusOK {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
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

func cleanLicenseList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, l := range in {
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
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
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

// cloneStrings returns a deep copy of a string slice.
func cloneStrings(src []string) []string {
	if src == nil {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// getGitHubHTTPClient returns a singleton HTTP client configured with a timeout
// suitable for GitHub API requests.
func getGitHubHTTPClient() *nethttp.Client {
	githubHTTPClientOnce.Do(func() {
		githubHTTPClient = &nethttp.Client{Timeout: 10 * time.Second}
	})
	return githubHTTPClient
}

// fetchLicensesFromGitHubRaw attempts to download license files directly from
// GitHub's raw content domain. This avoids the overhead of a full git clone
// when only the license text is needed.
func fetchLicensesFromGitHubRaw(ctx context.Context, owner, repo, version string) ([]string, error) {
	ref := deriveGitRef(version)
	if ref == "" {
		return nil, fmt.Errorf("unable to derive git ref")
	}
	client := getGitHubHTTPClient()
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	seen := map[string]struct{}{}
	var out []string
	for _, name := range defaultLicenseFilenames {
		url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, ref, name)
		req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "deputy-license-scan")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == nethttp.StatusNotFound {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != nethttp.StatusOK {
			resp.Body.Close()
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || len(data) == 0 {
			continue
		}
		for _, id := range DetectLicenseIDs(data) {
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no license files via raw")
	}
	sort.Strings(out)
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
