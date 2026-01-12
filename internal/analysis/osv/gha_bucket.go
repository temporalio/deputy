package osv

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/cache"
	"github.com/picatz/deputy/internal/cache/disk"
	"github.com/picatz/deputy/internal/collections"
	"github.com/picatz/deputy/internal/httputil"
	"github.com/picatz/deputy/internal/purlx"
	"github.com/picatz/deputy/internal/vulnerability"
	"golang.org/x/mod/semver"
	"golang.org/x/sync/singleflight"
)

var (
	// ghaAllZipURL is the OSV GCS bucket URL holding GitHub Actions advisories.
	// It is a variable to allow tests to override the download source.
	ghaAllZipURL           = "https://storage.googleapis.com/osv-vulnerabilities/GitHub%20Actions/all.zip"
	ghaCacheSubdir         = "osv-gha"
	ghaZipFilename         = "all.zip"
	ghaDownloadTTL         = 6 * time.Hour
	ghaDownloadLimit int64 = 50 << 20 // 50MB safety cap
)

type ghaZipMeta struct {
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

func ghaZipMetaPath(zipPath string) string {
	return zipPath + ".meta.json"
}

// readGHAMeta reads cache metadata if available. Returns empty struct on any error.
func readGHAMeta(zipPath string) ghaZipMeta {
	var meta ghaZipMeta
	p := ghaZipMetaPath(zipPath)
	b, err := os.ReadFile(p)
	if err != nil {
		return meta
	}
	_ = json.Unmarshal(b, &meta) // best-effort; corrupt meta is handled gracefully
	return meta
}

// writeGHAMeta writes cache metadata. Failures are silently ignored as metadata
// is an optimization for conditional requests, not required for correctness.
func writeGHAMeta(zipPath string, meta ghaZipMeta) {
	p := ghaZipMetaPath(zipPath)
	b, err := json.Marshal(meta)
	if err != nil {
		return
	}
	_ = os.WriteFile(p, b, 0o644) // best-effort cache metadata
}

// ghaHTTPTimeout is the overall request timeout for GHA vulnerability fetches.
const ghaHTTPTimeout = 30 * time.Second

// ghaHTTPClient uses retryable HTTP for resilience when downloading the GHA
// vulnerability zip from Google Cloud Storage, which may have transient failures.
var ghaHTTPClient = httputil.NewRetryableClient(ghaHTTPTimeout)

var ghaGitHubTokenEnvVar = "GITHUB_TOKEN"

type ghaVulnIndex struct {
	byPkg map[string][]osvschema.Vulnerability
}

var (
	ghaIndexMu      sync.RWMutex
	ghaIndex        *ghaVulnIndex
	ghaIndexBuiltAt time.Time

	// ghaIndexTTL controls how long an in-memory GHA vulnerability index is
	// considered valid. It defaults to ghaDownloadTTL and exists separately so
	// tests can override refresh behavior without mutating the on-disk TTL.
	ghaIndexTTL = ghaDownloadTTL

	// ghaIndexBuildGroup ensures only one goroutine builds/refreshes the GHA
	// vulnerability index at a time using singleflight request coalescing.
	// Without this, concurrent vulnerability scans could trigger redundant
	// downloads of the ~50MB all.zip file from the OSV GCS bucket.
	ghaIndexBuildGroup singleflight.Group
)

// queryOSVGHABucketBatch looks up GitHub Actions vulnerabilities using the
// OSV GCS bucket (all.zip) because the OSV API does not currently accept the
// "GitHub Actions" ecosystem for querybatch.
func queryOSVGHABucketBatch(ctx context.Context, client Client, pkgs []PkgInput) ([]Vulnerability, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	idx, err := loadGHAVulnIndex(ctx)
	if err != nil {
		return nil, err
	}
	var aliasCache sync.Map
	var majorTagCache sync.Map
	var out []Vulnerability
	for _, p := range pkgs {
		version := strings.TrimSpace(p.Version)
		if version == "" {
			continue
		}
		normalized := normalizeGitHubActionsInput(p)
		if normalized.Name == "" {
			continue
		}
		effective := normalized
		effectiveVersion := version
		if resolved := resolveGitHubActionsVersion(ctx, &majorTagCache, normalized.Name, version); resolved != "" {
			effectiveVersion = resolved
			effective.Version = resolved
		}
		candidates := idx.byPkg[strings.ToLower(normalized.Name)]
		if len(candidates) == 0 {
			continue
		}
		for _, v := range candidates {
			if !versionAffectedByGHARanges(v, effective, effectiveVersion) {
				continue
			}
			base := ProcessOSVVulnerability(v, effective)
			base.Affected = true
			var extras []Vulnerability
			skip := false
			for _, alias := range v.Aliases {
				if client == nil {
					continue
				}
				var aliasV *osvschema.Vulnerability
				if cached, ok := aliasCache.Load(alias); ok {
					aliasV = cached.(*osvschema.Vulnerability)
				} else {
					aliasV, err = getCachedVuln(ctx, client, alias)
					if err != nil || aliasV == nil {
						continue
					}
					aliasCache.Store(alias, aliasV)
				}
				if !slices.ContainsFunc(aliasV.Affected, func(a osvschema.Affected) bool {
					return matchesPackage(a.Package, effective)
				}) {
					continue
				}
				if !versionAffectedByGHARanges(*aliasV, effective, effectiveVersion) {
					skip = true
					break
				}
				{
					pv := ProcessOSVVulnerability(*aliasV, effective)
					extras = append(extras, pv)
				}
			}
			if skip {
				continue
			}
			all := append([]Vulnerability{base}, extras...)
			if sev, typ := FindBestSeverity(all); sev != "" {
				base.Severity, base.SeverityType = sev, typ
			}
			fixSet := collections.NewSet[string]()
			var importSets [][]vulnerabilityv1.AffectedImport
			if len(base.AffectedImports) > 0 {
				importSets = append(importSets, base.AffectedImports)
			}
			dbSpecific := maps.Clone(base.DatabaseSpecific)
			for _, vv := range all {
				for _, f := range vv.FixedVersions {
					fixSet.Add(f)
				}
				base.Aliases = append(base.Aliases, vv.Aliases...)
				if len(vv.AffectedImports) > 0 {
					importSets = append(importSets, vv.AffectedImports)
				}
				dbSpecific = vulnerability.MergeStringMap(dbSpecific, vv.DatabaseSpecific)
			}
			aliasSet := collections.NewSet[string]()
			uniqAliases := make([]string, 0, len(base.Aliases))
			for _, a := range append([]string{base.ID}, base.Aliases...) {
				if !aliasSet.Add(a) {
					continue
				}
				if a != base.ID {
					uniqAliases = append(uniqAliases, a)
				}
			}
			base.Aliases = uniqAliases
			base.FixedVersions = base.FixedVersions[:0]
			for f := range fixSet.All() {
				base.FixedVersions = append(base.FixedVersions, f)
			}
			base.AffectedImports = vulnerability.MergeAffectedImports(importSets...)
			base.DatabaseSpecific = dbSpecific
			out = append(out, base)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func resolveGitHubActionsVersion(ctx context.Context, cache *sync.Map, name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return ""
	}
	major, ok := parseGHAMajorRef(version)
	if !ok && normalizeSemverVersion(version) != "" {
		// Fully specified semver doesn't need resolution.
		// Note: x/mod/semver treats "v4" as valid ("v4.0.0"), but we still want to
		// resolve the rolling major tag when the user requested "v4".
		return ""
	}
	if !ok {
		return ""
	}

	key := name + "@v" + strconv.Itoa(major)
	if cache != nil {
		if v, ok := cache.Load(key); ok {
			if s, ok := v.(string); ok {
				return s
			}
			return ""
		}
	}

	resolved := resolveGHAMajorTagToHighestSemver(ctx, name, major)
	if cache != nil {
		cache.Store(key, resolved)
	}
	return resolved
}

// parseGHAMajorRef extracts the major version from a GitHub Actions "rolling major"
// reference like "v4" or "4".
//
// It returns ok=false for non-major refs such as "v4.2.0", commit SHAs, or empty
// strings.
func parseGHAMajorRef(v string) (int, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	v = strings.TrimPrefix(v, "v")
	if strings.Contains(v, ".") {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

var ghaListRemoteRefs = listRemoteRefs

// resolveGHAMajorTagToHighestSemver resolves a major tag (like "v4") by listing
// remote tags and selecting the highest "v4.x.y" tag.
//
// This is needed because GitHub Actions often recommend pinning to a major
// (or major.minor) tag, which is a moving reference.
func resolveGHAMajorTagToHighestSemver(ctx context.Context, repo string, major int) string {
	if major <= 0 {
		return ""
	}
	repo = strings.TrimSpace(repo)
	if repo == "" || !strings.Contains(repo, "/") {
		return ""
	}
	remoteURL := fmt.Sprintf("https://github.com/%s.git", repo)
	refs, err := ghaListRemoteRefs(ctx, remoteURL)
	if err != nil || len(refs) == 0 {
		return ""
	}

	wantPrefix := "v" + strconv.Itoa(major) + "."
	best := ""
	for _, refName := range refs {
		if !strings.HasPrefix(refName, "refs/tags/") {
			continue
		}
		name := strings.TrimPrefix(refName, "refs/tags/")
		name = strings.TrimSuffix(name, "^{}")
		name = strings.TrimSpace(name)
		if name == "" || !strings.HasPrefix(name, wantPrefix) {
			continue
		}
		sv := normalizeSemverVersion(name)
		if sv == "" {
			continue
		}
		if best == "" || semver.Compare(sv, best) > 0 {
			best = sv
		}
	}
	return best
}

// gitHubAuthFromEnv returns a GitHub HTTPS auth method if GITHUB_TOKEN is set.
func gitHubAuthFromEnv() transport.AuthMethod {
	tok := strings.TrimSpace(os.Getenv(ghaGitHubTokenEnvVar))
	if tok == "" {
		return nil
	}
	return &githttp.BasicAuth{Username: "x-access-token", Password: tok}
}

// listRemoteRefs lists remote refs using go-git (similar to `git ls-remote`).
func listRemoteRefs(ctx context.Context, remoteURL string) ([]string, error) {
	remoteURL = strings.TrimSpace(remoteURL)
	if remoteURL == "" {
		return nil, fmt.Errorf("empty remote URL")
	}
	r := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{Name: "origin", URLs: []string{remoteURL}})
	refs, err := r.ListContext(ctx, &git.ListOptions{Auth: gitHubAuthFromEnv()})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		if ref == nil {
			continue
		}
		name := ref.Name()
		if name == "" || name == plumbing.HEAD {
			continue
		}
		out = append(out, name.String())
	}
	return out, nil
}

// normalizeGitHubActionsInput canonicalizes a GitHub Actions PkgInput for matching:
// - Ecosystem is set to "GitHub Actions"
// - github.com/ prefix is stripped from names
// - If Name is empty but PURL is github, Name is derived from PURL.
func normalizeGitHubActionsInput(in PkgInput) PkgInput {
	out := in
	out.Ecosystem = string(osvschema.EcosystemGitHubActions)
	name := strings.TrimSpace(out.Name)
	if name == "" && out.PURL != "" {
		if pu, err := purlx.ParseLoose(out.PURL); err == nil && purlx.IsGitHubActionsType(pu.Type) {
			if pu.Namespace != "" {
				name = pu.Namespace + "/" + pu.Name
			} else {
				name = pu.Name
			}
		}
	}
	name = strings.TrimPrefix(name, "github.com/")
	out.Name = strings.Trim(name, "/")
	return out
}

// versionAffectedByGHARanges evaluates whether pkg.Version falls within any
// SEMVER or ECOSYSTEM ranges for GitHub Actions vulnerabilities.
func versionAffectedByGHARanges(v osvschema.Vulnerability, pkg PkgInput, version string) bool {
	if strings.TrimSpace(version) == "" {
		version = pkg.Version
	}
	cur := normalizeSemverVersion(version)
	if cur == "" {
		for _, a := range v.Affected {
			if matchesPackage(a.Package, pkg) {
				return true
			}
		}
		return false
	}
	for _, a := range v.Affected {
		if !matchesPackage(a.Package, pkg) {
			continue
		}
		if len(a.Ranges) == 0 {
			return true
		}
		foundComparableRange := false
		for _, r := range a.Ranges {
			rt := strings.ToUpper(string(r.Type))
			if rt != "SEMVER" && rt != "ECOSYSTEM" {
				continue
			}
			foundComparableRange = true
			introduced := "v0.0.0"
			introducedSet := false // Track whether an "introduced" event was encountered
			for _, e := range r.Events {
				if e.Introduced != "" {
					introducedSet = true
					// "0" means "all versions from the beginning"
					if e.Introduced == "0" {
						introduced = "v0.0.0"
					} else if intro := normalizeSemverVersion(e.Introduced); intro != "" {
						introduced = intro
					}
				}
				if e.Fixed != "" {
					fixed := normalizeSemverVersion(e.Fixed)
					if fixed != "" && semver.Compare(cur, introduced) >= 0 && semver.Compare(cur, fixed) < 0 {
						return true
					}
					introduced = "v0.0.0"
					introducedSet = false
				}
			}
			// Check if we're still in an open-ended "introduced" range (no fixed event)
			if introducedSet && semver.Compare(cur, introduced) >= 0 {
				return true
			}
		}
		if !foundComparableRange {
			return true
		}
	}
	return false
}

// normalizeSemverVersion converts a potentially non-canonical version into a
// semver string acceptable to x/mod/semver (v-prefixed), returning "" if invalid.
func normalizeSemverVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return ""
	}
	if canon := semver.Canonical(v); canon != "" {
		return canon
	}
	return v
}

// loadGHAVulnIndex memoizes a parsed view of the GitHub Actions all.zip bucket.
func loadGHAVulnIndex(ctx context.Context) (*ghaVulnIndex, error) {
	// Check if cache is bypassed via --no-cache flag
	bypassCache := cache.ShouldBypassSource(ctx, "osv")

	ghaIndexMu.RLock()
	idx := ghaIndex
	builtAt := ghaIndexBuiltAt
	ttl := ghaIndexTTL
	ghaIndexMu.RUnlock()

	if !bypassCache && idx != nil && ttl > 0 && time.Since(builtAt) < ttl {
		return idx, nil
	}

	buildCtx := ctx
	if buildCtx != nil {
		buildCtx = context.WithoutCancel(buildCtx)
	}

	v, err, _ := ghaIndexBuildGroup.Do("build", func() (any, error) {
		return buildGHAVulnIndex(buildCtx)
	})
	if err != nil {
		// If we have a previously built index, prefer serving it over failing
		// requests when refresh fails.
		if idx != nil {
			return idx, nil
		}
		return nil, err
	}
	newIdx := v.(*ghaVulnIndex)

	ghaIndexMu.Lock()
	ghaIndex = newIdx
	ghaIndexBuiltAt = time.Now()
	ghaIndexMu.Unlock()

	return newIdx, nil
}

// buildGHAVulnIndex downloads (or reuses cached) all.zip and indexes vulnerabilities by package name.
func buildGHAVulnIndex(ctx context.Context) (*ghaVulnIndex, error) {
	zipPath, err := ensureGHACacheZip(ctx)
	if err != nil {
		return nil, err
	}
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("open GHA all.zip: %w", err)
	}
	defer reader.Close()
	// Pre-allocate map with estimated capacity based on JSON file count
	jsonCount := 0
	for _, f := range reader.File {
		if f != nil && strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			jsonCount++
		}
	}
	idx := &ghaVulnIndex{byPkg: make(map[string][]osvschema.Vulnerability, jsonCount)}
	for _, f := range reader.File {
		if f == nil || !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close() // best-effort; already read all data
		if err != nil {
			continue
		}
		var vuln osvschema.Vulnerability
		if err := json.Unmarshal(b, &vuln); err != nil {
			continue
		}
		for _, a := range vuln.Affected {
			if a.Package.Name == "" {
				continue
			}
			if !strings.EqualFold(a.Package.Ecosystem, string(osvschema.EcosystemGitHubActions)) {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(a.Package.Name))
			if key == "" {
				continue
			}
			idx.byPkg[key] = append(idx.byPkg[key], vuln)
		}
	}
	return idx, nil
}

// ensureGHACacheZip ensures a recent copy of all.zip exists on disk and returns its path.
// The zip is refreshed on a TTL to keep results aligned with OSV releases.
func ensureGHACacheZip(ctx context.Context) (string, error) {
	// Check if cache is bypassed via --no-cache flag
	bypassCache := cache.ShouldBypassSource(ctx, "osv")

	base := disk.BaseDir()
	if base == "" {
		tmp, err := os.MkdirTemp("", "deputy-osv-gha-*")
		if err != nil {
			return "", fmt.Errorf("no cache dir: %w", err)
		}
		base = tmp
	}
	dir := filepath.Join(base, ghaCacheSubdir)
	path := filepath.Join(dir, ghaZipFilename)
	if !bypassCache {
		if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
			if time.Since(fi.ModTime()) < ghaDownloadTTL {
				return path, nil
			}
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

	meta := readGHAMeta(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ghaAllZipURL, nil)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(meta.ETag) != "" {
		req.Header.Set("If-None-Match", meta.ETag)
	}
	if strings.TrimSpace(meta.LastModified) != "" {
		req.Header.Set("If-Modified-Since", meta.LastModified)
	}
	resp, err := ghaHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		now := time.Now()
		_ = os.Chtimes(path, now, now) // best-effort TTL refresh
		return path, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("download GHA all.zip: %s", resp.Status)
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	limited := &io.LimitedReader{R: resp.Body, N: ghaDownloadLimit}
	if _, err := io.Copy(f, limited); err != nil {
		_ = f.Close()      // best-effort cleanup
		_ = os.Remove(tmp) // best-effort cleanup
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp) // best-effort cleanup
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp) // best-effort cleanup
		return "", err
	}

	writeGHAMeta(path, ghaZipMeta{
		ETag:         strings.TrimSpace(resp.Header.Get("ETag")),
		LastModified: strings.TrimSpace(resp.Header.Get("Last-Modified")),
	})
	return path, nil
}
