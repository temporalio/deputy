package mise

import "strings"

// PruneLockedVersions removes mise.lock entries for a tool whose locked
// version stale reports true, along with their attached platform sub-tables,
// and returns the updated content plus whether anything was removed.
//
// This exists for remediation: after Deputy bumps a tool's declared version in
// the config, a leftover lock entry still pins the old (vulnerable) version,
// and lock resolution falls back to it, so scans keep reporting the version
// the fix just removed. The entry cannot be updated in place because its
// per-platform checksums, sizes, and URLs describe the old artifact; inventing
// them for the new version would make the lockfile lie and break mise's own
// verification. Removing the stale entry keeps the lockfile honest and lets
// `mise install` re-resolve and re-lock the new version.
//
// toolKeys lists the lock table keys that identify the tool (typically the
// config key and its backend-stripped short name). Content is edited line-wise
// so unrelated entries, comments, and formatting survive byte-for-byte.
func PruneLockedVersions(content []byte, toolKeys []string, stale func(version string) bool) ([]byte, bool) {
	if len(toolKeys) == 0 || stale == nil {
		return content, false
	}
	isTool := func(segs []string) bool {
		if len(segs) < 2 || segs[0] != "tools" {
			return false
		}
		for _, k := range toolKeys {
			if segs[1] == k {
				return true
			}
		}
		return false
	}

	lines := strings.Split(string(content), "\n")
	out := make([]string, 0, len(lines))
	changed := false

	for i := 0; i < len(lines); i++ {
		segs, isArray, ok := lockHeaderPath(lines[i])
		if !ok || !isArray || len(segs) != 2 || !isTool(segs) {
			out = append(out, lines[i])
			continue
		}

		// A [[tools.<key>]] entry: it spans until the next header that is not
		// one of its own sub-tables (platform data lives in single-bracket
		// [tools.<key>...] headers attached to the preceding entry).
		end := i + 1
		version := ""
		sawSubHeader := false
		for end < len(lines) {
			if segs2, isArr2, ok2 := lockHeaderPath(lines[end]); ok2 {
				if isArr2 || !isTool(segs2) {
					break
				}
				sawSubHeader = true
			} else if !sawSubHeader && version == "" {
				version = lockEntryVersion(lines[end])
			}
			end++
		}

		if !stale(version) {
			out = append(out, lines[i:end]...)
			i = end - 1
			continue
		}

		// Drop the entry. Swallow one trailing blank line so the surrounding
		// blocks do not end up separated by doubled blanks.
		changed = true
		if end < len(lines) && strings.TrimSpace(lines[end]) == "" &&
			len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
			end++
		}
		i = end - 1
	}

	if !changed {
		return content, false
	}
	return []byte(strings.Join(out, "\n")), true
}

// lockHeaderPath parses a TOML table header line from a mise.lock file,
// returning its key path segments and whether it is an array-of-tables
// ([[...]]) header. ok is false for non-header lines.
func lockHeaderPath(line string) (segs []string, isArray bool, ok bool) {
	s := strings.TrimSpace(line)
	if !strings.HasPrefix(s, "[") {
		return nil, false, false
	}
	isArray = strings.HasPrefix(s, "[[")
	open, closing := "[", "]"
	if isArray {
		open, closing = "[[", "]]"
	}
	s = strings.TrimPrefix(s, open)
	// Allow a trailing comment after the header.
	if idx := strings.Index(s, closing); idx >= 0 {
		rest := strings.TrimSpace(s[idx+len(closing):])
		if rest != "" && !strings.HasPrefix(rest, "#") {
			return nil, false, false
		}
		s = s[:idx]
	} else {
		return nil, false, false
	}
	segs = SplitKeyPath(strings.TrimSpace(s))
	if len(segs) == 0 {
		return nil, false, false
	}
	return segs, isArray, true
}

// lockEntryVersion extracts the version value from a `version = "..."` line at
// the top level of a lock entry, or "" when the line declares something else.
func lockEntryVersion(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}
	eq := strings.IndexByte(trimmed, '=')
	if eq < 0 || strings.TrimSpace(trimmed[:eq]) != "version" {
		return ""
	}
	val := strings.TrimSpace(trimmed[eq+1:])
	if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') {
		if end := strings.IndexByte(val[1:], val[0]); end >= 0 {
			return val[1 : 1+end]
		}
		return ""
	}
	if idx := strings.IndexAny(val, " \t#"); idx >= 0 {
		val = val[:idx]
	}
	return val
}

// SplitKeyPath splits a TOML key path into its dotted segments, unquoting
// quoted segments, so `tools."npm:lodash".version` yields
// [tools npm:lodash version]. It returns nil for anything that is not a
// well-formed key path. Both the mise.lock pruner and the config rewriter use
// it to interpret keys the same way mise's TOML parser does.
func SplitKeyPath(key string) []string {
	var segs []string
	i := 0
	for i < len(key) {
		i = skipKeySpaces(key, i)
		if i >= len(key) {
			return nil
		}
		var seg string
		switch q := key[i]; q {
		case '"', '\'':
			end := strings.IndexByte(key[i+1:], q)
			if end < 0 {
				return nil
			}
			seg = key[i+1 : i+1+end]
			i = i + 2 + end
		default:
			start := i
			for i < len(key) && key[i] != '.' && key[i] != ' ' && key[i] != '\t' {
				i++
			}
			seg = key[start:i]
		}
		if seg == "" {
			return nil
		}
		segs = append(segs, seg)
		i = skipKeySpaces(key, i)
		if i < len(key) {
			if key[i] != '.' {
				return nil
			}
			i++
		}
	}
	return segs
}

// skipKeySpaces returns the first offset at or after i that is not a space or
// tab, for scanning TOML key paths.
func skipKeySpaces(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}
