package compare

import (
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
	parts := strings.Split(canonicalName, "/")
	if len(parts) == 0 {
		return canonicalName
	}
	if len(parts) == 1 {
		return parts[0]
	}
	// For github.com/user/repo style, return first 3 parts if available
	if len(parts) >= 3 && parts[0] == "github.com" {
		return strings.Join(parts[:3], "/")
	}
	// For other cases, return first 2 parts
	if len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
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
	rest := strings.TrimPrefix(name, "gopkg.in/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 {
		return name
	}
	if len(parts) == 1 {
		// gopkg.in/repo.vN -> github.com/go-repo/repo
		rv := parts[0]
		for i := len(rv) - 1; i >= 0; i-- {
			if rv[i] == '.' && i+1 < len(rv) && rv[i+1] == 'v' {
				ver := rv[i+2:]
				if ver != "" && allDigits(ver) {
					repo := rv[:i]
					return "github.com/go-" + repo + "/" + repo
				}
			}
		}
	} else {
		user := parts[0]
		for idx := 1; idx < len(parts); idx++ {
			p := parts[idx]
			for j := len(p) - 1; j >= 0; j-- {
				if p[j] == '.' && j+1 < len(p) && p[j+1] == 'v' {
					ver := p[j+2:]
					if ver != "" && allDigits(ver) {
						base := p[:j]
						// repo possibly in parts[1]
						result := "github.com/" + user
						if idx == 1 {
							result += "/" + base
						} else {
							result += "/" + parts[1]
						}
						for k := 2; k < idx; k++ {
							result += "/" + parts[k]
						}
						if idx > 1 {
							result += "/" + base
						}
						return result
					}
				}
			}
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
		parts := strings.Split(info.FullName, "/")
		last := parts[len(parts)-1]
		if len(last) > 1 && last[0] == 'v' && allDigits(last[1:]) {
			// parse number
			n := 0
			for _, r := range last[1:] {
				if r >= '0' && r <= '9' {
					n = n*10 + int(r-'0')
				} else {
					break
				}
			}
			if n > 0 {
				info.MajorVersion = n
			}
		}
	}
	// Handle gopkg.in style embedded suffixes (foo.v2) which are removed during
	// normalization so FullName == CanonicalName and the branch above does not
	// execute. We examine the original import path components for a trailing
	// .vN pattern.
	if info.MajorVersion == 1 && info.FullName == info.CanonicalName {
		origParts := strings.Split(info.OriginalName, "/")
		if len(origParts) > 0 {
			last := origParts[len(origParts)-1]
			// search from end for .v
			for i := len(last) - 1; i >= 2; i-- { // need at least 3 chars like x.v2
				if last[i] >= '0' && last[i] <= '9' { // potential digit sequence end
					// find start of digits
					j := i
					for j >= 0 && last[j] >= '0' && last[j] <= '9' {
						j--
					}
					// expect .v before digits
					if j >= 1 && last[j] == 'v' && last[j-1] == '.' {
						verDigits := last[j+1 : i+1]
						if verDigits != "" && allDigits(verDigits) {
							// parse
							n := 0
							for _, r := range verDigits {
								n = n*10 + int(r-'0')
							}
							if n > 0 {
								info.MajorVersion = n
								break
							}
						}
					}
					// continue scanning left of this digit block
					i = j
				}
			}
		}
	}
	return info
}

// CompareGoPackageVersions returns 1 for upgrade, -1 for downgrade, 0 otherwise.
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

type versionComparator func(baseVersion, targetVersion string) (int, bool)

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

func compareGoVersions(baseVersion, targetVersion string) (int, bool) {
	if baseVersion == "" || targetVersion == "" {
		return 0, false
	}
	return CompareGoPackageVersions(Change{BaseVersion: baseVersion, TargetVersion: targetVersion}), true
}

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

// ComparePackages computes changes between old and new package inventories.
// ComparePackages computes the dependency delta between two package slices.
// It indexes each slice by canonical import path and classifies additions,
// removals, upgrades, downgrades, and other updates while also tagging whether
// each resulting Change is a direct dependency in the target workspace.
//
// If deps is nil, direct dependencies are inferred from go.mod in the supplied
// workspace.
type pkgSummary struct {
	pkg       *extractor.Package
	ecosystem string
	canonical string
	module    string
	key       string
}

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

func (s pkgSummary) ecosystemName() string {
	if strings.TrimSpace(s.ecosystem) != "" {
		return s.ecosystem
	}
	return "unknown"
}

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
	return changes
}

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
