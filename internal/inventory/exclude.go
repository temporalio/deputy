package inventory

import (
	"fmt"
	"strings"

	"github.com/gobwas/glob"
)

// DefaultDependencyInstallDirs are directory names that unambiguously denote an
// installed or vendored third-party dependency tree, never a source-of-truth
// manifest location. A name qualifies only if it is the canonical install
// directory for an ecosystem and is not also a common source-directory name:
// that admits "node_modules", "site-packages", and "__pypackages__" but excludes
// ambiguous names that are frequently real source dirs ("vendor", "target",
// "build") and the virtualenv root (".venv"/"venv"), whose vendored manifests
// live under the unambiguous "site-packages" child matched here.
//
// This backs [IsDependencyInstallPath], used by the remediation guard to avoid
// emitting a fix against a manifest vendored inside an installed tree (a derived
// copy that cannot be edited in place). It is deliberately small and serves as a
// version-control-independent backstop, notably for non-git directory scans.
// Scoping a repository scan to its committed source of truth is handled
// separately by honoring version control, not by this list.
var DefaultDependencyInstallDirs = []string{
	"node_modules",
	"site-packages",
	"__pypackages__",
}

// IsDependencyInstallPath reports whether p traverses a dependency-install
// directory (see [DefaultDependencyInstallDirs]). Path separators may be "/" or
// "\\"; matching is per path segment, so "a/b/site-packages/pkg/Cargo.toml"
// matches while "my-site-packages.txt" does not. Used to keep remediation from
// targeting a manifest vendored inside an installed dependency tree.
func IsDependencyInstallPath(p string) bool {
	p = strings.ReplaceAll(strings.TrimSpace(p), "\\", "/")
	if p == "" {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		for _, dir := range DefaultDependencyInstallDirs {
			if seg == dir {
				return true
			}
		}
	}
	return false
}

// CompileExcludePaths compiles a set of path-exclusion glob patterns into a
// single matcher suitable for scalibr's SkipDirGlob. Patterns are matched
// against directory paths (slash-separated, relative to the scan root) during
// the filesystem walk; a match prunes the entire subtree from inventory.
//
// Pattern semantics (gitignore-flavored):
//   - Globs use '/' as the path separator; '**' matches across separators.
//   - A trailing "/" or "/**" is optional: ".bin", ".bin/", and ".bin/**" all
//     exclude the ".bin" subtree.
//   - A pattern WITHOUT a '/' matches a directory of that name at any depth, so
//     ".bin" excludes both "./.bin" and "internal/.bin".
//   - A pattern WITH a '/' is anchored to the scan root, so ".github/workflows"
//     excludes only that subdirectory while leaving the rest of ".github" intact.
//
// Returns (nil, nil) when no usable patterns are supplied, so callers can leave
// SkipDirGlob unset. Returns an error if any pattern is malformed rather than
// silently ignoring it.
func CompileExcludePaths(patterns []string) (glob.Glob, error) {
	globs := make(multiGlob, 0, len(patterns))
	for _, raw := range patterns {
		p := normalizeExcludePattern(raw)
		if p == "" {
			continue
		}
		g, err := glob.Compile(p, '/')
		if err != nil {
			return nil, fmt.Errorf("invalid exclude path pattern %q: %w", raw, err)
		}
		globs = append(globs, g)

		// Make bare names and "**/"-prefixed names depth-insensitive in BOTH
		// directions (gitignore-style): a slash-less name like "vendor" should
		// also match "a/b/vendor", and an explicit "**/vendor" should also match
		// a top-level "vendor" (gobwas '**' requires the leading separator, so
		// it would otherwise miss the root). Register the complementary variant.
		var variant string
		switch {
		case !strings.Contains(p, "/"):
			variant = "**/" + p
		case strings.HasPrefix(p, "**/"):
			variant = strings.TrimPrefix(p, "**/")
		}
		if variant != "" {
			gd, err := glob.Compile(variant, '/')
			if err != nil {
				return nil, fmt.Errorf("invalid exclude path pattern %q: %w", raw, err)
			}
			globs = append(globs, gd)
		}
	}
	if len(globs) == 0 {
		return nil, nil
	}
	return globs, nil
}

// normalizeExcludePattern trims whitespace and any trailing "/" or "/**" so that
// directory and subtree spellings resolve to the same directory-path glob.
func normalizeExcludePattern(p string) string {
	p = strings.TrimSpace(p)
	for {
		switch {
		case strings.HasSuffix(p, "/**"):
			p = p[:len(p)-3]
		case strings.HasSuffix(p, "/"):
			p = p[:len(p)-1]
		default:
			return p
		}
	}
}

// multiGlob matches if any of its component globs match. It satisfies
// glob.Glob so it can be passed directly to scalibr's SkipDirGlob.
type multiGlob []glob.Glob

// Match reports whether s matches any component glob.
func (m multiGlob) Match(s string) bool {
	for _, g := range m {
		if g.Match(s) {
			return true
		}
	}
	return false
}
