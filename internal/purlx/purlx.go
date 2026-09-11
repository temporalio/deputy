// Package purlx provides Deputy-specific helpers for working with PURLs.
//
// Deputy relies on github.com/google/osv-scalibr/purl for most parsing and
// formatting. That package validates PURL types against a fixed allowlist, so
// this package offers "loose" parsing for emerging types such as
// pkg:githubactions (see https://github.com/package-url/purl-spec/issues/698).
package purlx

import (
	"fmt"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	scalpurl "github.com/google/osv-scalibr/purl"
	packageurl "github.com/package-url/packageurl-go"

	"github.com/temporalio/deputy/internal/forge"
)

const (
	// TypeGitHubActions is the emerging PURL type for GitHub Actions dependencies.
	// This matches the package-url spec proposal and existing ecosystem usage.
	TypeGitHubActions = "githubactions"

	// TypeMise is the PURL type for tools managed by mise (mise-en-place):
	// language runtimes and tools installed from mise's many backends (aqua,
	// ubi, cargo, npm, pipx, go, gem, asdf). It matches the value OSV-SCALIBR's
	// upstream runtime/mise extractor uses (purl.TypeMise), so Deputy's mise
	// inventory stays forward-compatible with a future SCALIBR upgrade.
	TypeMise = "mise"

	// TypeAsdf is the PURL type for tools declared in the asdf .tool-versions
	// format. mise also reads .tool-versions, but the format originates with
	// asdf, and OSV-SCALIBR models it as a distinct ecosystem (purl.TypeAsdf)
	// from mise.toml. Deputy emits pkg:asdf for .tool-versions content to stay
	// congruent with that upstream split.
	TypeAsdf = "asdf"
)

// AsdfPURL formats an asdf PURL (pkg:asdf/<name>@<version>) matching the form
// emitted by OSV-SCALIBR's runtime/asdf extractor. Returns "" when name is empty.
func AsdfPURL(name, version string) string {
	return looseTypePURL(TypeAsdf, name, version)
}

// looseTypePURL builds a pkg:<type>/<name>@<version> string for an emerging
// PURL type that SCALIBR's allowlist does not yet recognize. It uses SCALIBR's
// purl formatter (whose String delegates to packageurl-go) for consistency with
// the rest of Deputy's inventory pipeline. Returns "" when name is empty.
func looseTypePURL(ptype, name, version string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	return scalpurl.PackageURL{
		Type:    ptype,
		Name:    name,
		Version: strings.TrimSpace(version),
	}.String()
}

// MisePURL formats a mise PURL for a tool name and version, matching the
// pkg:mise/<name>@<version> form emitted by OSV-SCALIBR's runtime/mise
// extractor. The backend, when present, is carried in package metadata rather
// than the PURL so identity matches upstream. Returns "" when name is empty.
func MisePURL(name, version string) string {
	return looseTypePURL(TypeMise, name, version)
}

// ParseLoose parses a PURL string without validating the type against a
// fixed allowlist. It is appropriate for tooling that needs to read PURLs
// for emerging types.
func ParseLoose(purlStr string) (packageurl.PackageURL, error) {
	purlStr = strings.TrimSpace(purlStr)
	if purlStr == "" {
		return packageurl.PackageURL{}, fmt.Errorf("empty purl")
	}
	return packageurl.FromString(purlStr)
}

// EquivalentIgnoringVersion reports whether a and b refer to the same package,
// ignoring version and subpath. Comparison is case-insensitive for type,
// namespace, and name.
func EquivalentIgnoringVersion(a, b string) bool {
	pa, errA := ParseLoose(a)
	pb, errB := ParseLoose(b)
	if errA != nil || errB != nil {
		return strings.EqualFold(a, b)
	}
	return strings.EqualFold(pa.Type, pb.Type) &&
		strings.EqualFold(pa.Namespace, pb.Namespace) &&
		strings.EqualFold(pa.Name, pb.Name)
}

// IsGitHubActionsType reports whether t is a GitHub Actions-related PURL type.
// Deputy accepts both the emerging githubactions type and the legacy github
// type for compatibility.
func IsGitHubActionsType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case TypeGitHubActions, scalpurl.TypeGithub:
		return true
	default:
		return false
	}
}

// GitHubActionsPURL formats a canonical GitHub Actions PURL using namespace
// (owner), name (repo), optional version (ref), and optional subpath (#...).
// Subpaths are normalized to be relative and free of traversal.
func GitHubActionsPURL(owner, repo, version, subpath string) string {
	owner = strings.TrimSpace(strings.Trim(owner, "/"))
	repo = strings.TrimSpace(strings.Trim(repo, "/"))
	if owner == "" || repo == "" {
		return ""
	}
	subpath = cleanSubpath(subpath)
	return scalpurl.PackageURL{
		Type:      TypeGitHubActions,
		Namespace: owner,
		Name:      repo,
		Version:   strings.TrimSpace(version),
		Subpath:   subpath,
	}.String()
}

// GitHubActionsPURLFromPackage builds a canonical GitHub Actions PURL from a
// scalibr package. It best-effort reads a "Subpath" string field from pkg.Metadata
// (when present) to populate the PURL subpath without coupling to a specific
// metadata type.
func GitHubActionsPURLFromPackage(pkg *extractor.Package) string {
	if pkg == nil {
		return ""
	}
	owner, repo, rest := forge.SplitOwnerRepoRest(pkg.Name)
	subpath := rest
	if mdSub := subpathFromMetadata(pkg.Metadata); mdSub != "" {
		subpath = mdSub
	}
	return GitHubActionsPURL(owner, repo, pkg.Version, subpath)
}

// subpathFromMetadata attempts to extract a "Subpath" string field from a metadata object.
// It supports pointers and ignores non-string fields.
func subpathFromMetadata(md any) string {
	if md == nil {
		return ""
	}
	v := reflect.ValueOf(md)
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return ""
		}
		v = v.Elem()
	}
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return ""
	}
	f := v.FieldByName("Subpath")
	if !f.IsValid() || f.Kind() != reflect.String {
		return ""
	}
	return strings.TrimSpace(f.String())
}

func cleanSubpath(subpath string) string {
	s := filepath.ToSlash(strings.TrimSpace(subpath))
	s = strings.TrimPrefix(s, "./")
	s = strings.TrimPrefix(s, "/")
	if s == "" || s == "." {
		return ""
	}
	s = path.Clean(s)
	s = strings.TrimPrefix(s, "./")
	if s == "." || s == ".." || strings.HasPrefix(s, "../") {
		return ""
	}
	return s
}

// NPMPackageName reassembles an npm package name from a PURL's namespace and
// name, restoring the "@scope/name" form npm itself uses.
//
// OSV-SCALIBR splits a scoped name into the PURL namespace with its leading "@"
// already attached, while other PURL producers leave the "@" off, so it is added
// only when it is missing. An empty namespace means the package is unscoped.
func NPMPackageName(namespace, name string) string {
	if namespace == "" {
		return name
	}
	if !strings.HasPrefix(namespace, "@") {
		namespace = "@" + namespace
	}
	return namespace + "/" + name
}
