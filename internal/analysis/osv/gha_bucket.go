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
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/cache"
	"github.com/temporalio/deputy/internal/cache/disk"
	"github.com/temporalio/deputy/internal/collections"
	"github.com/temporalio/deputy/internal/httputil"
	"github.com/temporalio/deputy/internal/purlx"
	"github.com/temporalio/deputy/internal/vulnerability"
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

// ghaHTTPClient uses retryable HTTP with SSRF protection for resilience when
// downloading the GHA vulnerability zip from Google Cloud Storage, which may
// have transient failures. SafeDialer prevents DNS rebinding attacks.
var ghaHTTPClient = httputil.NewSafeRetryableClient(ghaHTTPTimeout)

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
	var versionResolveCache sync.Map
	var out []Vulnerability
	for _, p := range pkgs {
		normalized := normalizeGitHubActionsInput(p)
		version := strings.TrimSpace(normalized.Version)
		if version == "" {
			continue
		}
		if normalized.Name == "" {
			continue
		}
		effective := normalized
		effectiveVersion := version
		if resolved := resolveGitHubActionsVersion(ctx, &versionResolveCache, normalized.Name, version); resolved != "" {
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

// resolveGitHubActionsVersion returns a comparable semver when a GitHub Actions
// ref is resolvable without changing its meaning. It resolves rolling major
// tags such as "v4" or "v4.2" and commit SHA pins that point at release tags;
// exact semver refs and unresolved refs return "" so callers can keep the
// original version and avoid guessing.
func resolveGitHubActionsVersion(ctx context.Context, cache *sync.Map, name, version string) string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return ""
	}
	if isGitCommitSHA(version) {
		return resolveGitHubActionsCommitVersion(ctx, cache, name, version)
	}
	prefix, ok := parseGHAFloatingRefPrefix(version)
	if !ok && normalizeSemverVersion(version) != "" {
		// Fully specified semver doesn't need resolution.
		// Note: x/mod/semver treats "v4" as valid ("v4.0.0"), but we still want
		// to resolve moving refs when the user requested "v4" or "v4.2".
		return ""
	}
	if !ok {
		return ""
	}

	key := name + "@" + prefix
	if cache != nil {
		if v, ok := cache.Load(key); ok {
			if s, ok := v.(string); ok {
				return s
			}
			return ""
		}
	}

	resolved := resolveGHAFloatingRefToHighestSemver(ctx, name, prefix)
	if cache != nil {
		cache.Store(key, resolved)
	}
	return resolved
}

// resolveGitHubActionsCommitVersion resolves a SHA-pinned action to a release
// semver when the commit maps unambiguously to one or more semver tags. The
// result is cached per action and SHA because scans often encounter the same
// action in multiple workflows.
func resolveGitHubActionsCommitVersion(ctx context.Context, cache *sync.Map, name, sha string) string {
	key := name + "@" + strings.ToLower(strings.TrimSpace(sha))
	if cache != nil {
		if v, ok := cache.Load(key); ok {
			if s, ok := v.(string); ok {
				return s
			}
			return ""
		}
	}

	resolved := resolveGHACommitToHighestSemverTag(ctx, name, sha)
	if cache != nil {
		cache.Store(key, resolved)
	}
	return resolved
}

// isGitCommitSHA reports whether v is a short or full hexadecimal Git commit
// SHA. It deliberately runs before rolling-major parsing so all-numeric commit
// prefixes are not mistaken for large major version tags.
func isGitCommitSHA(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 7 || len(v) > 40 {
		return false
	}
	for _, r := range v {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}

// parseGHAFloatingRefPrefix returns the semver tag prefix for a moving GitHub
// Actions ref such as "v4", "4", "v4.2", or "4.2". Fully specified versions,
// commit SHAs, and non-numeric refs return ok=false.
func parseGHAFloatingRefPrefix(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" || isGitCommitSHA(v) {
		return "", false
	}
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) != 1 && len(parts) != 2 {
		return "", false
	}
	nums := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return "", false
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return "", false
		}
		nums = append(nums, n)
	}
	if nums[0] <= 0 {
		return "", false
	}
	if len(nums) == 1 {
		return "v" + strconv.Itoa(nums[0]) + ".", true
	}
	return "v" + strconv.Itoa(nums[0]) + "." + strconv.Itoa(nums[1]) + ".", true
}

var ghaListRemoteRefs = listRemoteRefs

// ghaRemoteRef captures the ref name and object hash returned by a remote Git
// ref listing. Tests replace the listing function with deterministic refs so
// SHA-to-tag resolution does not need network access.
type ghaRemoteRef struct {
	Name string
	Hash string
}

var ghaListRemoteRefsWithHashes = listRemoteRefsWithHashes

// resolveGHAFloatingRefToHighestSemver resolves a moving GitHub Actions tag
// prefix by listing remote tags and selecting the highest matching semver tag.
//
// This is needed because GitHub Actions often recommend pinning to a major
// (or major.minor) tag, which is a moving reference.
func resolveGHAFloatingRefToHighestSemver(ctx context.Context, repo, wantPrefix string) string {
	wantPrefix = strings.TrimSpace(wantPrefix)
	if wantPrefix == "" {
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

// resolveGHACommitToHighestSemverTag maps a pinned commit SHA to the highest
// semver tag that points at that commit. It handles both lightweight tags and
// annotated tags via the peeled refs/tags/<tag>^{} ref exposed by ls-remote.
//
// If a short SHA prefix matches multiple distinct commits, the ref is treated as
// unresolved. That is safer than applying an arbitrary release version to an
// advisory range.
func resolveGHACommitToHighestSemverTag(ctx context.Context, repo, sha string) string {
	repo = strings.TrimSpace(repo)
	sha = strings.ToLower(strings.TrimSpace(sha))
	if repo == "" || !strings.Contains(repo, "/") || !isGitCommitSHA(sha) {
		return ""
	}
	remoteURL := fmt.Sprintf("https://github.com/%s.git", repo)
	refs, err := ghaListRemoteRefsWithHashes(ctx, remoteURL)
	if err != nil || len(refs) == 0 {
		return ""
	}

	best := ""
	matchedHashes := map[string]struct{}{}
	for _, ref := range refs {
		if !strings.HasPrefix(ref.Name, "refs/tags/") {
			continue
		}
		hash := strings.ToLower(ref.Hash)
		if !strings.HasPrefix(hash, sha) {
			continue
		}
		matchedHashes[hash] = struct{}{}
		tag := strings.TrimPrefix(ref.Name, "refs/tags/")
		tag = strings.TrimSuffix(tag, "^{}")
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		sv := normalizeSemverVersion(tag)
		if sv == "" {
			continue
		}
		if best == "" || semver.Compare(sv, best) > 0 {
			best = sv
		}
	}
	if len(matchedHashes) > 1 {
		return ""
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

// listRemoteRefsWithHashes lists remote refs and their object hashes using
// go-git. Annotated tags usually appear twice: the tag object itself and a
// peeled refs/tags/<tag>^{} ref pointing at the target commit.
func listRemoteRefsWithHashes(ctx context.Context, remoteURL string) ([]ghaRemoteRef, error) {
	remoteURL = strings.TrimSpace(remoteURL)
	if remoteURL == "" {
		return nil, fmt.Errorf("empty remote URL")
	}
	r := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{Name: "origin", URLs: []string{remoteURL}})
	refs, err := r.ListContext(ctx, &git.ListOptions{Auth: gitHubAuthFromEnv()})
	if err != nil {
		return nil, err
	}
	out := make([]ghaRemoteRef, 0, len(refs))
	for _, ref := range refs {
		if ref == nil {
			continue
		}
		name := ref.Name()
		if name == "" || name == plumbing.HEAD {
			continue
		}
		hash := ref.Hash().String()
		if hash == "" {
			continue
		}
		out = append(out, ghaRemoteRef{Name: name.String(), Hash: hash})
	}
	return out, nil
}

// normalizeGitHubActionsInput canonicalizes a GitHub Actions PkgInput for matching:
//   - Ecosystem is set to "GitHub Actions".
//   - github.com/ is stripped from action names.
//   - Name and Version are derived from GitHub Actions PURLs when present.
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
			if strings.TrimSpace(out.Version) == "" {
				out.Version = strings.TrimSpace(pu.Version)
			}
		}
	}
	name = strings.TrimPrefix(name, "github.com/")
	out.Name = strings.Trim(name, "/")
	return out
}

// versionAffectedByGHARanges evaluates whether version falls within a GitHub
// Actions advisory range for pkg. Non-semver refs only match advisories that do
// not publish ranges, or open-ended ranges introduced at "0" with no fix. A
// bounded range requires a comparable version so an unresolved SHA or moving tag
// is not reported as vulnerable by default.
func versionAffectedByGHARanges(v osvschema.Vulnerability, pkg PkgInput, version string) bool {
	if strings.TrimSpace(version) == "" {
		version = pkg.Version
	}
	cur := ""
	if _, floating := parseGHAFloatingRefPrefix(version); !floating {
		cur = normalizeSemverVersion(version)
	}
	if cur == "" {
		for _, a := range v.Affected {
			if !matchesPackage(a.Package, pkg) {
				continue
			}
			if len(a.Ranges) == 0 {
				return true
			}
			for _, r := range a.Ranges {
				if ghaRangeAppliesToUnresolvedRef(r) {
					return true
				}
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
				if e.LastAffected != "" {
					// Some advisories bound a range with last_affected instead of
					// fixed. Without this branch the range collapses to the
					// open-ended check below and reports every version above
					// introduced as affected. Mirror versionInGoSemverRange.
					lastAffected := normalizeSemverVersion(e.LastAffected)
					if lastAffected != "" && semver.Compare(cur, introduced) >= 0 && semver.Compare(cur, lastAffected) <= 0 {
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

// ghaRangeAppliesToUnresolvedRef reports whether an advisory range applies to
// a ref that Deputy could not resolve to a comparable semver. Only open-ended
// ranges introduced at "0" qualify; bounded ranges need a resolved version.
func ghaRangeAppliesToUnresolvedRef(r osvschema.Range) bool {
	rt := strings.ToUpper(string(r.Type))
	if rt != "SEMVER" && rt != "ECOSYSTEM" {
		return false
	}
	introducedAtZero := false
	for _, e := range r.Events {
		if e.Fixed != "" || e.LastAffected != "" || e.Limit != "" {
			return false
		}
		if e.Introduced == "0" {
			introducedAtZero = true
			continue
		}
		if e.Introduced != "" {
			return false
		}
	}
	return introducedAtZero
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
	if limited.N == 0 {
		// The response hit the safety cap and was truncated; a partial zip has
		// no valid central directory, so fail loudly instead of caching a file
		// that zip.OpenReader would silently reject.
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("GHA all.zip exceeds %d byte safety cap; increase ghaDownloadLimit", ghaDownloadLimit)
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
