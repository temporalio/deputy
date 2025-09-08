package compare

import (
	"os"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"golang.org/x/mod/semver"
)

// ChangeType classifies the kind of dependency transition observed between two
// inventories. A dependency may be newly Added, Removed, or Updated (version
// change and/or path canonicalization difference).
type ChangeType int

const (
	// Added indicates the dependency did not exist in the base inventory but
	// appears in the target inventory.
	Added ChangeType = iota
	// Removed indicates the dependency existed in the base inventory but is
	// absent from the target inventory.
	Removed
	// Updated indicates the dependency exists in both inventories but the
	// version and/or import path changed.
	Updated
)

// Change captures a single dependency delta between two scans. For Added
// entries BaseVersion/OldName are empty. For Removed entries TargetVersion is
// empty. Updated entries record both old and new identifying information.
//
// Ecosystem is currently always "go" but is modeled for future multi-ecosystem
// support. IsDirect is true when the module root appears explicitly (without
// "// indirect" annotation) in go.mod of the target workspace.
type Change struct {
	Name          string     // canonical or full import path in target inventory
	OldName       string     // previous path (may differ after canonicalization)
	TargetVersion string     // version in target inventory (for Added/Updated)
	BaseVersion   string     // version in base inventory (for Removed/Updated)
	ChangeType    ChangeType // classification of the change
	Ecosystem     string     // e.g. "go"
	IsDirect      bool       // true if a direct dependency in target go.mod
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

// getModuleRoot safely extracts the module root from a canonical package name
// getModuleRoot derives a module root approximation from a canonical import
// path. It attempts to return a stable identifier suitable for determining
// direct vs indirect status by mapping import paths like
//
//	github.com/user/repo/subpkg/internal/foo
//
// to the module root github.com/user/repo. For non GitHub style hosts it
// returns the first two path segments when available.
func getModuleRoot(canonicalName string) string {
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

// getDirectDependencies reads go.mod in cwd and returns direct module roots.
// getDirectDependencies parses go.mod in the current working directory and
// returns a set keyed by module path for direct dependencies (i.e. those
// without the "// indirect" annotation). If go.mod cannot be read a set
// containing only "stdlib" is returned.
func getDirectDependencies() map[string]bool {
	deps := map[string]bool{"stdlib": true}
	data, err := os.ReadFile("go.mod")
	if err != nil {
		return deps
	}
	// naive parse: lines with no "// indirect"
	lines := strings.Split(string(data), "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "//") {
			continue
		}
		if strings.Contains(ln, "// indirect") {
			continue
		}
		// e.g., github.com/foo/bar v1.2.3
		fields := strings.Fields(ln)
		if len(fields) >= 2 && strings.Contains(fields[0], "/") {
			deps[fields[0]] = true
		}
	}
	return deps
}

// ComparePackages computes changes between old and new package inventories.
// ComparePackages computes the dependency delta between two package slices.
// It indexes each slice by canonical import path and classifies additions,
// removals, and updates while also tagging whether each resulting Change is a
// direct dependency in the target workspace.
func ComparePackages(oldPkgs, newPkgs []*extractor.Package) []Change {
	if len(oldPkgs) == 0 && len(newPkgs) == 0 {
		return nil
	}
	// Index by canonical name -> latest (by version)
	oldMap := map[string]*extractor.Package{}
	newMap := map[string]*extractor.Package{}
	for _, p := range oldPkgs {
		if p != nil && p.Name != "" {
			info := ParseGoPackage(p)
			oldMap[info.CanonicalName] = p
		}
	}
	for _, p := range newPkgs {
		if p != nil && p.Name != "" {
			info := ParseGoPackage(p)
			newMap[info.CanonicalName] = p
		}
	}

	deps := getDirectDependencies()
	var changes []Change
	// Removed or updated
	for canon, op := range oldMap {
		np, ok := newMap[canon]
		if !ok {
			changes = append(changes, Change{Name: op.Name, BaseVersion: op.Version, ChangeType: Removed, Ecosystem: "go", IsDirect: deps[getModuleRoot(canon)]})
			continue
		}
		if op.Version != np.Version || op.Name != np.Name {
			changes = append(changes, Change{Name: np.Name, OldName: op.Name, BaseVersion: op.Version, TargetVersion: np.Version, ChangeType: Updated, Ecosystem: "go", IsDirect: deps[getModuleRoot(canon)]})
		}
	}
	// Added
	for canon, np := range newMap {
		if _, ok := oldMap[canon]; !ok {
			changes = append(changes, Change{Name: np.Name, TargetVersion: np.Version, ChangeType: Added, Ecosystem: "go", IsDirect: deps[getModuleRoot(canon)]})
		}
	}
	return changes
}
