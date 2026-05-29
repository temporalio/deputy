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
)

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
