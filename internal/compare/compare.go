package compare

import (
	"cmp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/semantic"
	"golang.org/x/mod/semver"

	"github.com/picatz/deputy/internal/repository/workspace"
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
	ChangeType    ChangeType `json:"changeType"`    // numeric classification of the change
	Type          string     `json:"type"`          // string classification ("added","removed","updated","upgraded","downgraded")
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
func normalizeGoVersion(v string) string {
	if v == "" {
		return v
	}
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
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
			res := "github.com/" + user
			for k := 1; k < i; k++ {
				res += "/" + parts[k]
			}
			res += "/" + base
			if i+1 < len(parts) {
				res += "/" + strings.Join(parts[i+1:], "/")
			}
			return res
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
			verStr := info.FullName[idx+2:]
			if allDigits(verStr) {
				n := 0
				for _, r := range verStr {
					n = n*10 + int(r-'0')
				}
				if n > 0 {
					info.MajorVersion = n
				}
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
			verStr := lastSeg[idx+2:]
			if verStr != "" && allDigits(verStr) {
				n := 0
				for _, r := range verStr {
					n = n*10 + int(r-'0')
				}
				if n > 0 {
					info.MajorVersion = n
				}
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

// classifyGoChangeType derives a ChangeType based on Go semantic version ordering.
// When versions cannot be compared it falls back to Updated.
func classifyGoChangeType(baseVersion, targetVersion string) ChangeType {
	if baseVersion == "" || targetVersion == "" {
		return Updated
	}
	cmp := CompareGoPackageVersions(Change{BaseVersion: baseVersion, TargetVersion: targetVersion})
	switch {
	case cmp > 0:
		return Upgraded
	case cmp < 0:
		return Downgraded
	default:
		return Updated
	}
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
func semanticEcosystemName(ecosystem string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
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
	default:
		return "", false
	}
}

// compareGoVersions compares two Go versions.
func compareGoVersions(baseVersion, targetVersion string) (int, bool) {
	if baseVersion == "" || targetVersion == "" {
		return 0, false
	}
	return CompareGoPackageVersions(Change{BaseVersion: baseVersion, TargetVersion: targetVersion}), true
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

// GetDirectDependenciesFromGoMod parses a go.mod file and returns module roots
// for direct dependencies (those without "// indirect"). The returned set
// always includes "stdlib".
func GetDirectDependenciesFromGoMod(data []byte) map[string]bool {
	deps := map[string]bool{"stdlib": true}
	if len(data) == 0 {
		return deps
	}
	for ln := range strings.SplitSeq(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "//") {
			continue
		}
		if strings.Contains(ln, "// indirect") {
			continue
		}
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
			deps[GetModuleRoot(info.CanonicalName)] = true
		}
	}
	return deps
}

// GetDirectDependencies reads go.mod from the provided workspace and returns
// direct module roots. If go.mod cannot be read (missing or workspace nil)
// the returned set only contains "stdlib".
func GetDirectDependencies(ws workspace.FileReader) map[string]bool {
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

// summarizePackage extracts comparison metadata from a package.
func summarizePackage(p *extractor.Package) (string, pkgSummary) {
	if p == nil || p.Name == "" {
		return "", pkgSummary{}
	}
	ecos := strings.TrimSpace(p.Ecosystem())
	if ecos == "" && p.PURLType != "" {
		ecos = p.PURLType
	}
	meta := pkgSummary{pkg: p, ecosystem: ecos}
	if strings.EqualFold(ecos, "Go") {
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
	meta.canonical = name
	if ecos == "" {
		meta.key = name
		return meta.key, meta
	}
	meta.key = strings.ToLower(ecos) + "|" + name
	return meta.key, meta
}

// ecosystemName returns the ecosystem name or "unknown" if empty.
func (s pkgSummary) ecosystemName() string {
	if strings.TrimSpace(s.ecosystem) != "" {
		return s.ecosystem
	}
	return "unknown"
}

// ComparePackages computes the dependency delta between two package slices.
// It indexes each slice by canonical import path and classifies additions,
// removals, upgrades, downgrades, and other updates while also tagging whether
// each resulting Change is a direct dependency in the target workspace.
//
// If deps is nil, direct dependencies are inferred from go.mod in the supplied
// workspace.
func ComparePackages(oldPkgs, newPkgs []*extractor.Package, goDirect map[string]bool, pkgDirect map[string]bool, ws workspace.FileReader) []Change {
	if len(oldPkgs) == 0 && len(newPkgs) == 0 {
		return nil
	}
	oldMap := map[string]pkgSummary{}
	newMap := map[string]pkgSummary{}
	for _, p := range oldPkgs {
		if key, meta := summarizePackage(p); key != "" {
			oldMap[key] = meta
		}
	}
	for _, p := range newPkgs {
		if key, meta := summarizePackage(p); key != "" {
			newMap[key] = meta
		}
	}
	if goDirect == nil {
		goDirect = GetDirectDependencies(ws)
	}
	var changes []Change
	for key, oldMeta := range oldMap {
		newMeta, ok := newMap[key]
		if !ok {
			changes = append(changes, Change{
				Name:        oldMeta.pkg.Name,
				BaseVersion: oldMeta.pkg.Version,
				ChangeType:  Removed,
				Type:        Removed.String(),
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
				Type:          ct.String(),
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
			Type:          Added.String(),
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
		return strings.Compare(a.Name, b.Name)
	})

	return changes
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
