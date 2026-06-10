package compare

import (
	"cmp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/semantic"
	"golang.org/x/mod/semver"

	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/repository/workspace"
)

// ChangeType classifies the kind of dependency transition observed between two
// inventories. A dependency may be newly Added, Removed, Upgraded, Downgraded,
// or Updated (non-semver change such as an import path canonicalization).
type ChangeType int

const (
	// Added indicates the dependency did not exist in the base inventory but
	// appears in the target inventory.
	Added ChangeType = iota
	// Removed indicates the dependency existed in the base inventory but is
	// absent from the target inventory.
	Removed
	// Updated indicates the dependency exists in both inventories but changed in
	// a way that does not amount to a semantic version upgrade or downgrade—most
	// commonly an import path canonicalization.
	Updated
	// Upgraded indicates the dependency exists in both inventories and the
	// target version is semantically greater than the base version.
	Upgraded
	// Downgraded indicates the dependency exists in both inventories and the
	// target version is semantically lower than the base version.
	Downgraded
)

func (c ChangeType) String() string {
	switch c {
	case Added:
		return "added"
	case Removed:
		return "removed"
	case Updated:
		return "updated"
	case Upgraded:
		return "upgraded"
	case Downgraded:
		return "downgraded"
	default:
		return "unknown"
	}
}

// Change captures a single dependency delta between two scans. For Added
// entries BaseVersion/OldName are empty. For Removed entries TargetVersion is
// empty. Updated entries record both old and new identifying information.
//
// Ecosystem is currently always "go" but is modeled for future multi-ecosystem
// support. IsDirect is true when the module root appears explicitly (without
// "// indirect" annotation) in go.mod of the target workspace.
type Change struct {
	Name          string     `json:"name"`          // canonical or full import path in target inventory
	OldName       string     `json:"oldName"`       // previous path (may differ after canonicalization)
	TargetVersion string     `json:"targetVersion"` // version in target inventory (for Added/Updated)
	BaseVersion   string     `json:"baseVersion"`   // version in base inventory (for Removed/Updated)
	ChangeType    ChangeType `json:"changeType"`    // classification of the change
	Ecosystem     string     `json:"ecosystem"`     // e.g. "go", "npm"
	IsDirect      bool       `json:"isDirect"`      // true if a direct dependency when known (currently Go)
}

// GoPackageInfo represents a parsed interpretation of an import path possibly
// containing a semantic major version suffix (e.g. /v2) or a historical vanity
// host (gopkg.in). CanonicalName removes redundant major version path segments
// (except v0/v1 which remain inline by Go convention) while FullName preserves
// the original post-normalization path.
type GoPackageInfo struct {
	OriginalName  string // original raw name provided by the extractor
	FullName      string // normalized path (vanity hosts resolved)
	CanonicalName string // path with superfluous major suffix trimmed
	Version       string // semantic version string as reported by extractor
	MajorVersion  int    // parsed major version (defaults to 1)
}

// GetModuleRoot safely extracts the module root from a canonical package name
//
// GetModuleRoot derives a module root approximation from a canonical import
// path. It attempts to return a stable identifier suitable for determining
// direct vs indirect status by mapping import paths like
//
//	github.com/user/repo/subpkg/internal/foo
//
// to the module root github.com/user/repo. For non GitHub style hosts it
// returns the first two path segments when available.
func GetModuleRoot(canonicalName string) string {
	host, rest, ok := strings.Cut(canonicalName, "/")
	if !ok {
		return canonicalName
	}
	user, rest2, ok := strings.Cut(rest, "/")
	if !ok {
		return canonicalName
	}
	if host == "github.com" {
		repo, _, _ := strings.Cut(rest2, "/")
		return host + "/" + user + "/" + repo
	}
	return host + "/" + user
}

// normalizeGoVersion ensures semantic versions are prefixed with a leading 'v'
// so they can be safely compared with golang.org/x/mod/semver utilities.
// Delegates to the canonical implementation in the ecosystem package.
func normalizeGoVersion(v string) string {
	return ecosystem.Go.NormalizeVersion(v)
}

// NormalizeGopkgInURL converts gopkg.in URLs to their canonical GitHub repository names.
//
// https://labix.org/gopkg.in
// https://ayada.dev/posts/vanity-url-for-go-packages/
// NormalizeGopkgInURL returns a GitHub canonical import path for legacy
// gopkg.in style module URLs when possible. If the path is not a gopkg.in
// import it is returned unchanged. The transformation follows the historical
// mapping defined by the vanity service (see https://labix.org/gopkg.in).
func NormalizeGopkgInURL(name string) string {
	if !strings.HasPrefix(name, "gopkg.in/") {
		return name
	}
	rest := name[9:] // "gopkg.in/"

	parts := strings.Split(rest, "/")
	if len(parts) == 0 {
		return name
	}

	// Helper to check and extract .vN
	parseVersion := func(s string) (base string, ok bool) {
		idx := strings.LastIndex(s, ".v")
		if idx == -1 {
			return "", false
		}
		ver := s[idx+2:]
		if ver != "" && allDigits(ver) {
			return s[:idx], true
		}
		return "", false
	}

	// Case 1: gopkg.in/pkg.v3 (single segment)
	if len(parts) == 1 {
		if base, ok := parseVersion(parts[0]); ok {
			return "github.com/go-" + base + "/" + base
		}
		return name
	}

	// Case 2: gopkg.in/user/repo.vN/...
	// Iterate to find the versioned segment.
	user := parts[0]
	for i := 1; i < len(parts); i++ {
		if base, ok := parseVersion(parts[i]); ok {
			// Found versioned segment at i.
			// Reconstruct: github.com/user/part1/.../base/...
			var res strings.Builder
			res.WriteString("github.com/" + user)
			for k := 1; k < i; k++ {
				res.WriteString("/" + parts[k])
			}
			res.WriteString("/" + base)
			if i+1 < len(parts) {
				res.WriteString("/" + strings.Join(parts[i+1:], "/"))
			}
			return res.String()
		}
	}

	return name
}

// allDigits reports whether s contains only 0-9 runes.
func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// parseDigits converts a string of digits to an integer.
// Returns 0 if the string is empty or contains non-digit characters.
func parseDigits(s string) int {
	if s == "" || !allDigits(s) {
		return 0
	}
	n := 0
	for _, r := range s {
		n = n*10 + int(r-'0')
	}
	return n
}

// IsRelativePathModule reports whether name looks like a relative filesystem path
// rather than a valid Go module path. This detects replace directive targets like
// "../..", "./local", or "../../.." which are local development artifacts.
func IsRelativePathModule(name string) bool {
	return strings.HasPrefix(name, "./") || strings.HasPrefix(name, "../") || name == "." || name == ".."
}

// ExtractCanonicalPackageName trims superfluous major version suffixes (e.g.
// /v2, /v3) from an import path except for v0 and v1 which remain part of the
// canonical module path per Go module path semantics. gopkg.in names are first
// normalized to their GitHub equivalents.
func ExtractCanonicalPackageName(name string) string {
	// If gopkg.in, normalize to GitHub style first
	normalized := NormalizeGopkgInURL(name)
	parts := strings.Split(normalized, "/")
	if len(parts) == 0 {
		return normalized
	}
	last := parts[len(parts)-1]
	if strings.HasPrefix(last, "v") && allDigits(last[1:]) {
		// v1: keep; v0 keep
		if last == "v1" || last == "v0" {
			return normalized
		}
		return strings.Join(parts[:len(parts)-1], "/")
	}
	return normalized
}

// ParseGoPackage converts an extractor.Package into structured GoPackageInfo
// performing normalization and major version extraction.
func ParseGoPackage(pkg *extractor.Package) GoPackageInfo {
	normalized := NormalizeGopkgInURL(pkg.Name)
	info := GoPackageInfo{
		OriginalName:  pkg.Name,
		FullName:      normalized,
		CanonicalName: ExtractCanonicalPackageName(pkg.Name),
		Version:       pkg.Version,
		MajorVersion:  1,
	}
	if info.FullName != info.CanonicalName {
		// Extract version from the suffix of FullName (e.g. .../v2)
		if idx := strings.LastIndex(info.FullName, "/v"); idx != -1 {
			if n := parseDigits(info.FullName[idx+2:]); n > 0 {
				info.MajorVersion = n
			}
		}
	}
	// Handle gopkg.in style embedded suffixes (foo.v2) which are removed during
	// normalization so FullName == CanonicalName. We examine the original import
	// path's last segment for a .vN pattern.
	if info.MajorVersion == 1 && info.FullName == info.CanonicalName {
		lastSeg := info.OriginalName
		if idx := strings.LastIndex(info.OriginalName, "/"); idx != -1 {
			lastSeg = info.OriginalName[idx+1:]
		}
		if idx := strings.LastIndex(lastSeg, ".v"); idx != -1 {
			if n := parseDigits(lastSeg[idx+2:]); n > 0 {
				info.MajorVersion = n
			}
		}
	}
	return info
}

// CompareGoPackageVersions compares BaseVersion and TargetVersion of a Change
// returning 1 if TargetVersion is a semantic upgrade, -1 if a downgrade, and 0
// if versions are identical or unparsable.
func CompareGoPackageVersions(c Change) int {
	oldV := normalizeGoVersion(c.BaseVersion)
	newV := normalizeGoVersion(c.TargetVersion)
	return semver.Compare(newV, oldV)
}

// versionComparator is a function type for comparing two versions.
type versionComparator func(baseVersion, targetVersion string) (int, bool)

// selectChangeType determines the type of change between two versions for a given ecosystem.
func selectChangeType(ecosystem, baseVersion, targetVersion string) ChangeType {
	comp := comparatorForEcosystem(ecosystem)
	if comp != nil {
		if cmp, ok := comp(baseVersion, targetVersion); ok {
			switch {
			case cmp > 0:
				return Upgraded
			case cmp < 0:
				return Downgraded
			default:
				return Updated
			}
		}
	}
	if baseVersion == targetVersion {
		return Updated
	}
	return Updated
}

// comparatorForEcosystem returns a version comparison function for the specified ecosystem.
func comparatorForEcosystem(ecosystem string) versionComparator {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "go", "golang":
		return compareGoVersions
	}
	if canonical, ok := semanticEcosystemName(ecosystem); ok {
		return func(baseVersion, targetVersion string) (int, bool) {
			return compareSemanticVersions(baseVersion, targetVersion, canonical)
		}
	}
	return nil
}

// semanticEcosystemName maps a raw ecosystem string to its canonical semantic versioning ecosystem name.
// The canonical names are those expected by the osv-scalibr semantic versioning library.
func semanticEcosystemName(ecosystem string) (string, bool) {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	// Handle ecosystems with version suffixes (e.g., "Debian:11" -> "debian")
	if idx := strings.Index(eco, ":"); idx != -1 {
		eco = eco[:idx]
	}
	switch eco {
	case "npm", "yarn", "pnpm":
		return "npm", true
	case "pypi", "pip", "pipenv", "poetry", "python":
		return "PyPI", true
	case "composer", "packagist":
		return "Packagist", true
	case "cargo", "crates.io", "rust":
		return "crates.io", true
	case "maven":
		return "Maven", true
	case "nuget":
		return "NuGet", true
	case "rubygems", "gem", "bundler":
		return "RubyGems", true
	case "cran":
		return "CRAN", true
	case "hex":
		return "Hex", true
	case "pub":
		return "Pub", true
	case "swiftpm", "swift", "swifturl":
		return "SwiftURL", true
	case "ghc":
		return "GHC", true
	case "hackage":
		return "Hackage", true
	case "conancenter":
		return "ConanCenter", true
	case "bitnami":
		return "Bitnami", true
	// OS-level package ecosystems (container images)
	case "debian":
		return "Debian", true
	case "ubuntu":
		return "Ubuntu", true
	case "alpine":
		return "Alpine", true
	case "red hat", "rhel", "redhat":
		return "Red Hat", true
	case "centos":
		return "Red Hat", true // CentOS uses Red Hat versioning
	case "rocky", "rocky linux":
		return "Rocky Linux", true
	case "alma", "almalinux":
		return "AlmaLinux", true
	case "opensuse":
		return "openSUSE", true
	case "suse", "sles":
		return "SUSE", true
	default:
		return "", false
	}
}

// compareGoVersions compares two Go versions.
// Returns (0, false) if either version is empty or invalid (e.g., "(devel)").
func compareGoVersions(baseVersion, targetVersion string) (int, bool) {
	if baseVersion == "" || targetVersion == "" {
		return 0, false
	}
	// Normalize and validate both versions
	oldV := normalizeGoVersion(baseVersion)
	newV := normalizeGoVersion(targetVersion)
	// If either version is invalid (like "(devel)"), don't make upgrade/downgrade claims
	if !semver.IsValid(oldV) || !semver.IsValid(newV) {
		return 0, false
	}
	return semver.Compare(newV, oldV), true
}

// compareSemanticVersions compares two versions using the specified ecosystem's semantic versioning rules.
func compareSemanticVersions(baseVersion, targetVersion, ecosystem string) (int, bool) {
	base := strings.TrimSpace(baseVersion)
	target := strings.TrimSpace(targetVersion)
	if base == "" || target == "" {
		return 0, false
	}
	tv, err := semantic.Parse(target, ecosystem)
	if err != nil {
		return 0, false
	}
	cmp, err := tv.CompareStr(base)
	if err != nil {
		return 0, false
	}
	return cmp, true
}

// GetMainModuleFromGoMod parses a go.mod file and returns the main module path
// (the "module" declaration). Returns empty string if not found.
func GetMainModuleFromGoMod(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	for ln := range strings.SplitSeq(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "module ") {
			fields := strings.Fields(ln)
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}
	return ""
}

// GetDirectDependenciesFromGoMod parses a go.mod file and returns module paths
// for direct dependencies (those without "// indirect"). The returned set
// always includes "stdlib" and "go".
//
// The map stores:
//   - Exact module paths from go.mod marked as direct (value = true)
//   - Module roots for matching subpackage import paths (value = true, if any
//     direct module has that root)
//
// Indirect modules (those with "// indirect") are stored with value = false
// to explicitly mark them as NOT direct. This allows proper handling of Go
// submodules: if go.mod has "github.com/bytedance/sonic" as direct but
// "github.com/bytedance/sonic/loader" as indirect, only "sonic" is marked
// direct, not "sonic/loader".
func GetDirectDependenciesFromGoMod(data []byte) map[string]bool {
	deps := map[string]bool{"stdlib": true, "go": true}
	if len(data) == 0 {
		return deps
	}
	for ln := range strings.SplitSeq(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "//") {
			continue
		}
		isIndirect := strings.Contains(ln, "// indirect")
		fields := strings.Fields(ln)
		if len(fields) < 2 {
			continue
		}
		candidate := fields[0]
		if candidate == "require" && len(fields) >= 3 {
			candidate = fields[1]
		}
		if strings.Contains(candidate, "/") {
			info := ParseGoPackage(&extractor.Package{Name: candidate})
			// Store exact module path with its direct/indirect status.
			// For indirect modules, we explicitly store false so that
			// submodules like "foo/bar/loader" don't inherit the direct
			// status from their parent module "foo/bar".
			if isIndirect {
				// Only set to false if not already marked as direct
				// (a module appearing both as direct and indirect should be direct)
				if _, exists := deps[info.CanonicalName]; !exists {
					deps[info.CanonicalName] = false
				}
			} else {
				deps[info.CanonicalName] = true
				// For direct modules, also store module root for matching
				// subpackage import paths within the module
				root := GetModuleRoot(info.CanonicalName)
				if root != info.CanonicalName {
					// Only set root if not already explicitly set by an exact match
					if _, exists := deps[root]; !exists {
						deps[root] = true
					}
				}
			}
		}
	}
	return deps
}

// GetDirectDependencies reads go.mod from the provided workspace and returns
// direct module roots. If go.mod cannot be read (missing or workspace nil)
// the returned set only contains "stdlib".
func GetDirectDependencies(ws workspace.ReadableFS) map[string]bool {
	if ws == nil {
		return map[string]bool{"stdlib": true}
	}
	data, err := ws.ReadFile("go.mod")
	if err != nil {
		return map[string]bool{"stdlib": true}
	}
	return GetDirectDependenciesFromGoMod(data)
}

// pkgSummary holds metadata about a package for comparison purposes.
type pkgSummary struct {
	pkg       *extractor.Package
	ecosystem string
	canonical string
	module    string
	key       string
}

// normalizeEcosystemForComparison returns a normalized ecosystem name suitable for
// comparing packages across different versions of the same OS distribution.
// For example, "Debian:11" and "Debian:12" both normalize to "debian" so that
// packages can be properly matched and compared between OS versions.
func normalizeEcosystemForComparison(ecos string) string {
	ecos = strings.ToLower(strings.TrimSpace(ecos))
	if ecos == "" {
		return ""
	}
	// Strip version suffix from OS distributions (e.g., "debian:11" -> "debian")
	if before, _, ok := strings.Cut(ecos, ":"); ok {
		base := before
		// Only strip version for known OS distributions
		switch base {
		case "debian", "ubuntu", "alpine", "fedora", "centos", "rhel", "rocky", "alma", "opensuse", "sles":
			return base
		}
	}
	return ecos
}

// summarizePackage extracts comparison metadata from a package.
func summarizePackage(p *extractor.Package) (string, pkgSummary) {
	if p == nil || p.Name == "" {
		return "", pkgSummary{}
	}
	ecos := strings.TrimSpace(p.Ecosystem().String())
	if ecos == "" && p.PURLType != "" {
		ecos = p.PURLType
	}
	meta := pkgSummary{pkg: p, ecosystem: ecos}
	if strings.EqualFold(ecos, "Go") {
		// Skip relative path replace directives (e.g., "../..", "./local").
		// These are local development artifacts from go.mod replace directives
		// pointing to filesystem paths, not actual module dependencies.
		if IsRelativePathModule(p.Name) {
			return "", pkgSummary{}
		}
		info := ParseGoPackage(p)
		meta.canonical = strings.ToLower(info.CanonicalName)
		meta.module = GetModuleRoot(info.CanonicalName)
		if meta.module == "" {
			meta.module = GetModuleRoot(p.Name)
		}
		meta.key = "go|" + meta.canonical
		return meta.key, meta
	}
	name := strings.ToLower(p.Name)
	// Apply ecosystem-specific name normalization
	normalizedEcos := normalizeEcosystemForComparison(ecos)
	switch {
	case isPyPIEcosystem(normalizedEcos):
		name = normalizePyPIName(name)
	case isCargoEcosystem(normalizedEcos):
		name = normalizeCargoName(name)
	case isNpmEcosystem(normalizedEcos):
		// npm names are already case-insensitive; ToLower above handles it
		// No additional normalization needed beyond lowercasing
	}
	meta.canonical = name
	if ecos == "" {
		meta.key = name
		return meta.key, meta
	}
	// Use normalized ecosystem for key to match packages across OS versions
	meta.key = normalizedEcos + "|" + name
	return meta.key, meta
}

// ecosystemName returns the ecosystem name or "unknown" if empty.
func (s pkgSummary) ecosystemName() string {
	if strings.TrimSpace(s.ecosystem) != "" {
		return s.ecosystem
	}
	return "unknown"
}

// isPyPIEcosystem returns true if the ecosystem is a PyPI/Python ecosystem.
func isPyPIEcosystem(eco string) bool {
	switch strings.ToLower(eco) {
	case "pypi", "pip", "pipenv", "poetry", "python":
		return true
	}
	return false
}

// isCargoEcosystem returns true if the ecosystem is a Cargo/Rust ecosystem.
func isCargoEcosystem(eco string) bool {
	switch strings.ToLower(eco) {
	case "cargo", "crates.io", "rust":
		return true
	}
	return false
}

// isNpmEcosystem returns true if the ecosystem is an npm/Node.js ecosystem.
func isNpmEcosystem(eco string) bool {
	switch strings.ToLower(eco) {
	case "npm", "yarn", "pnpm", "node":
		return true
	}
	return false
}

// normalizePyPIName normalizes a PyPI package name according to PEP 503.
// Per PEP 503, valid package names must be lowercase and consecutive runs of
// underscores, hyphens, and periods are replaced with a single hyphen.
// This ensures that "My_Package", "my-package", and "my.package" all match.
func normalizePyPIName(name string) string {
	if name == "" {
		return name
	}
	// Already lowercased by caller, but ensure it
	name = strings.ToLower(name)
	// Replace consecutive runs of [-_.] with a single hyphen
	var result strings.Builder
	result.Grow(len(name))
	inSeparator := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !inSeparator {
				result.WriteByte('-')
				inSeparator = true
			}
			// Skip additional separators in a run
		} else {
			result.WriteRune(r)
			inSeparator = false
		}
	}
	return result.String()
}

// normalizeCargoName normalizes a Cargo/crates.io package name per RFC 940.
// On crates.io, hyphens and underscores are equivalent: "serde-json" and
// "serde_json" refer to the same crate. We normalize to underscores to match
// Rust's internal convention (crate names in code use underscores).
func normalizeCargoName(name string) string {
	if name == "" {
		return name
	}
	// Crate names are case-insensitive on crates.io
	name = strings.ToLower(name)
	// Replace hyphens with underscores (Rust convention)
	return strings.ReplaceAll(name, "-", "_")
}

// CompareOptions configures package comparison behavior.
type CompareOptions struct {
	// GoDirect is a set of Go module roots that are direct dependencies.
	GoDirect map[string]bool
	// PkgDirect is a set of package keys that are direct dependencies.
	PkgDirect map[string]bool
	// Workspace is used to read go.mod if GoDirect is nil.
	Workspace workspace.ReadableFS
	// ExcludeMainModules is a set of Go module paths to exclude from comparison
	// (typically the main module(s) of the project being analyzed).
	ExcludeMainModules map[string]bool
}

// ComparePackages computes the dependency delta between two package slices.
// It indexes each slice by canonical import path and classifies additions,
// removals, upgrades, downgrades, and other updates while also tagging whether
// each resulting Change is a direct dependency in the target workspace.
//
// If deps is nil, direct dependencies are inferred from go.mod in the supplied
// workspace.
func ComparePackages(oldPkgs, newPkgs []*extractor.Package, goDirect map[string]bool, pkgDirect map[string]bool, ws workspace.ReadableFS) []Change {
	return ComparePackagesWithOptions(oldPkgs, newPkgs, CompareOptions{
		GoDirect:  goDirect,
		PkgDirect: pkgDirect,
		Workspace: ws,
	})
}

// ComparePackagesWithOptions computes the dependency delta with configurable options.
func ComparePackagesWithOptions(oldPkgs, newPkgs []*extractor.Package, opts CompareOptions) []Change {
	if len(oldPkgs) == 0 && len(newPkgs) == 0 {
		return nil
	}
	oldMap := map[string]pkgSummary{}
	newMap := map[string]pkgSummary{}
	for _, p := range oldPkgs {
		if key, meta := summarizePackage(p); key != "" {
			// Skip excluded main modules
			if opts.ExcludeMainModules != nil && shouldExcludeModule(meta, opts.ExcludeMainModules) {
				continue
			}
			oldMap[key] = meta
		}
	}
	for _, p := range newPkgs {
		if key, meta := summarizePackage(p); key != "" {
			// Skip excluded main modules
			if opts.ExcludeMainModules != nil && shouldExcludeModule(meta, opts.ExcludeMainModules) {
				continue
			}
			newMap[key] = meta
		}
	}
	goDirect := opts.GoDirect
	if goDirect == nil {
		goDirect = GetDirectDependencies(opts.Workspace)
	}
	pkgDirect := opts.PkgDirect
	var changes []Change
	for key, oldMeta := range oldMap {
		newMeta, ok := newMap[key]
		if !ok {
			changes = append(changes, Change{
				Name:        oldMeta.pkg.Name,
				BaseVersion: oldMeta.pkg.Version,
				ChangeType:  Removed,
				Ecosystem:   oldMeta.ecosystemName(),
				IsDirect:    isDirectForSummary(oldMeta, goDirect, pkgDirect),
			})
			continue
		}
		if oldMeta.pkg.Version != newMeta.pkg.Version || oldMeta.pkg.Name != newMeta.pkg.Name {
			ct := selectChangeType(newMeta.ecosystemName(), oldMeta.pkg.Version, newMeta.pkg.Version)
			changes = append(changes, Change{
				Name:          newMeta.pkg.Name,
				OldName:       oldMeta.pkg.Name,
				BaseVersion:   oldMeta.pkg.Version,
				TargetVersion: newMeta.pkg.Version,
				ChangeType:    ct,
				Ecosystem:     newMeta.ecosystemName(),
				IsDirect:      isDirectForSummary(newMeta, goDirect, pkgDirect),
			})
		}
	}
	for key, newMeta := range newMap {
		if _, ok := oldMap[key]; ok {
			continue
		}
		changes = append(changes, Change{
			Name:          newMeta.pkg.Name,
			TargetVersion: newMeta.pkg.Version,
			ChangeType:    Added,
			Ecosystem:     newMeta.ecosystemName(),
			IsDirect:      isDirectForSummary(newMeta, goDirect, pkgDirect),
		})
	}

	// Sort changes for consistent output: by change type priority, then name
	slices.SortFunc(changes, func(a, b Change) int {
		// Sort by change type: Upgraded, Downgraded, Added, Removed, Updated
		typePriority := func(ct ChangeType) int {
			switch ct {
			case Upgraded:
				return 0
			case Downgraded:
				return 1
			case Added:
				return 2
			case Removed:
				return 3
			default:
				return 4
			}
		}
		if n := cmp.Compare(typePriority(a.ChangeType), typePriority(b.ChangeType)); n != 0 {
			return n
		}
		return cmp.Compare(a.Name, b.Name)
	})

	return changes
}

// shouldExcludeModule checks if a package should be excluded based on its module path.
func shouldExcludeModule(meta pkgSummary, excludeModules map[string]bool) bool {
	if !strings.EqualFold(meta.ecosystem, "Go") {
		return false
	}
	// Check canonical name directly
	if excludeModules[meta.canonical] {
		return true
	}
	// Check module root
	if meta.module != "" && excludeModules[meta.module] {
		return true
	}
	return false
}

// isDirectForSummary determines if a package is a direct dependency.
func isDirectForSummary(meta pkgSummary, goDirect, pkgDirect map[string]bool) bool {
	if pkgDirect != nil && meta.key != "" {
		if pkgDirect[meta.key] {
			return true
		}
	}
	if !strings.EqualFold(meta.ecosystem, "Go") {
		return false
	}
	if goDirect == nil {
		return false
	}
	if meta.module == "" {
		return false
	}
	return goDirect[meta.module]
}
