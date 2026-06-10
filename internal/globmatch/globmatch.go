// Package globmatch matches relative, slash-separated paths against
// gitignore-flavored glob patterns with real recursive "**" support.
//
// It exists because Go's path.Match / filepath.Match are segment-bounded:
// "*" never crosses "/", and "**" is not special (it behaves like "*"). That
// silently breaks the common intent of patterns like "vendor/**" or
// "node_modules/**", which fail to match nested files. globmatch uses
// github.com/gobwas/glob with "/" as the separator so "**" is recursive, and
// expands each pattern into gitignore-style variants so bare names match at any
// depth and directory patterns match their whole subtree.
package globmatch

import (
	"fmt"
	"strings"

	"github.com/gobwas/glob"
)

// Matcher reports whether paths match any of a compiled set of patterns.
// The zero value matches nothing. Construct one with [Compile].
type Matcher struct {
	globs []glob.Glob
}

// Compile builds a Matcher from gitignore-flavored glob patterns.
//
// Patterns use "/" as the path separator; "*" matches within a single segment
// and "**" matches across segments (recursive). Inputs are normalized to use
// "/" so callers may pass OS-native paths. Whitespace is trimmed and blank
// patterns are ignored. Per-pattern semantics:
//
//   - A pattern WITHOUT a "/" (e.g. "*.key", "node_modules") matches an entry
//     of that name at any depth, and—when it names a directory—everything
//     beneath it (so "node_modules" also matches "a/node_modules/b.js").
//   - A pattern WITH a "/" (e.g. "config/*.yaml", "vendor/**") is anchored to
//     the path root unless it begins with "**/". A trailing "/**" is optional:
//     "vendor", "vendor/", and "vendor/**" all match the "vendor" subtree.
//
// Compile returns an error for malformed patterns rather than silently
// ignoring them.
func Compile(patterns []string) (*Matcher, error) {
	m := &Matcher{}
	seen := make(map[string]bool)
	add := func(expr string) error {
		if expr == "" || seen[expr] {
			return nil
		}
		g, err := glob.Compile(expr, '/')
		if err != nil {
			return err
		}
		seen[expr] = true
		m.globs = append(m.globs, g)
		return nil
	}

	for _, raw := range patterns {
		base := normalize(raw)
		if base == "" {
			continue
		}
		for _, expr := range expand(base) {
			if err := add(expr); err != nil {
				return nil, fmt.Errorf("invalid exclude pattern %q: %w", raw, err)
			}
		}
	}
	return m, nil
}

// MatchPath reports whether p (a relative path, any separator) matches.
func (m *Matcher) MatchPath(p string) bool {
	if m == nil || len(m.globs) == 0 {
		return false
	}
	p = strings.Trim(filepathToSlash(p), "/")
	if p == "" {
		return false
	}
	for _, g := range m.globs {
		if g.Match(p) {
			return true
		}
	}
	return false
}

// Empty reports whether the matcher has no usable patterns.
func (m *Matcher) Empty() bool {
	return m == nil || len(m.globs) == 0
}

// normalize converts separators to "/", trims whitespace, and strips any
// trailing "/" or "/**" so directory and subtree spellings collapse to one
// base form (so "vendor", "vendor/", and "vendor/**" are equivalent).
func normalize(p string) string {
	p = strings.TrimSpace(filepathToSlash(p))
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

// expand turns a normalized base pattern into the set of glob expressions that
// implement the gitignore-flavored semantics documented on Compile.
func expand(base string) []string {
	out := []string{base, base + "/**"}
	switch {
	case !strings.Contains(base, "/"):
		// Bare name: match at any depth (and its subtree at any depth).
		out = append(out, "**/"+base, "**/"+base+"/**")
	case strings.HasPrefix(base, "**/"):
		// Already any-depth; also allow a root-level match of the remainder.
		rest := strings.TrimPrefix(base, "**/")
		out = append(out, rest, rest+"/**")
	}
	return out
}

// filepathToSlash converts OS path separators to "/" without importing
// path/filepath semantics elsewhere; callers usually pass slash paths already.
func filepathToSlash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}
