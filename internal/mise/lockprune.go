package mise

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

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
		sawVersion := false
		sawSubHeader := false
		for end < len(lines) {
			if segs2, isArr2, ok2 := lockHeaderPath(lines[end]); ok2 {
				if isArr2 || !isTool(segs2) {
					break
				}
				sawSubHeader = true
			} else if !sawSubHeader && !sawVersion {
				v, readable := lockEntryVersion(lines[end])
				if !readable {
					// A version this cannot decode is a version it cannot call
					// stale, and a value that runs past this line leaves the
					// entry's extent unknown too. Deleting on either guess
					// would discard integrity metadata for something Deputy
					// never identified, so the whole edit is abandoned and the
					// caller reports no change rather than a wrong one.
					return content, false
				}
				if v != "" {
					version, sawVersion = v, true
				}
			}
			end++
		}

		if !stale(version) {
			out = append(out, lines[i:end]...)
			i = end - 1
			continue
		}

		// Blank lines and comments trailing the entry introduce whatever comes
		// next, so they are not the entry's to delete: an annotation sitting
		// above the following [[tools...]] header documents that entry.
		drop := end
		for drop > i+1 {
			prev := strings.TrimSpace(lines[drop-1])
			if prev == "" || strings.HasPrefix(prev, "#") {
				drop--
				continue
			}
			break
		}
		// The blank line separating this entry from what follows belonged to
		// it, so take one with the entry; any remaining trivia introduces the
		// next entry and is handed back.
		if drop < end && strings.TrimSpace(lines[drop]) == "" {
			drop++
		}

		changed = true
		i = drop - 1
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
// the top level of a lock entry. It returns "" for a line that declares
// something else, and ok is false when the line declares a version this reader
// cannot decode: an undefined escape, an unterminated token, or a multi-line
// value that carries on past this line.
//
// Both halves of the assignment are read as a TOML parser reads them. The key
// goes through [SplitKeyPath], so a quoted `"version"` names the same field as
// a bare one, exactly as [ParseLock] decodes it.
//
// A quoted value is decoded, not copied. [ParseLock] and inventory read
// `version = "1.22.12"` as 1.22.12, and the plan the pruner is given
// carries that decoded version, so comparing the raw bytes never matches: the
// stale entry survives, lock resolution serves it back, and the config the fix
// just edited is reported at the vulnerable version again. All four of TOML's
// string forms are read, because a lockfile may spell a version with any of
// them and mise resolves them all the same way.
func lockEntryVersion(line string) (version string, ok bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", true
	}
	eq := strings.IndexByte(trimmed, '=')
	if eq < 0 {
		return "", true
	}
	// The key is read the way a TOML parser reads it, not compared as written:
	// TOML lets a bare key be spelled as a quoted one, so `"version"` names the
	// same field as `version` and [ParseLock] decodes both. Matching the raw
	// bytes misses the quoted spelling, and the entry then goes to the stale
	// predicate with no version at all, which either keeps a stale entry alive
	// or deletes an entry on a version this never read.
	if segs := SplitKeyPath(strings.TrimSpace(trimmed[:eq])); len(segs) != 1 || segs[0] != "version" {
		return "", true
	}
	val := strings.TrimSpace(trimmed[eq+1:])
	if val == "" {
		return "", false
	}
	if val[0] == '"' || val[0] == '\'' {
		end, terminated := TOMLStringEnd(val, 0)
		if !terminated {
			return "", false
		}
		if rest := strings.TrimSpace(val[end:]); rest != "" && !strings.HasPrefix(rest, "#") {
			return "", false
		}
		token := val[:end]
		// [UnquoteTOMLString] hands back a token it cannot read unchanged. A
		// decoded value is always shorter than its token, which still carries
		// its delimiters, so equality is how this learns the decode failed.
		decoded := UnquoteTOMLString(token)
		if decoded == token {
			return "", false
		}
		return decoded, true
	}
	// A bare token is not a TOML string at all, so there is nothing to decode;
	// it is compared as written, the way it always was.
	if idx := strings.IndexAny(val, " \t#"); idx >= 0 {
		val = val[:idx]
	}
	return val, true
}

// TOMLStringEnd returns the offset just past the TOML string token that opens
// at s[i], which must be a quote character. It covers all four of TOML's
// string forms: the single-line basic and literal strings, which end at their
// first unescaped closing quote and never span a line, and their multi-line
// counterparts, which may. ok is false when the token is unterminated, which
// is how a caller learns that the value continues on a line it has not
// gathered yet or that the file is malformed.
//
// Every scanner that has to step over a TOML string goes through it, the
// config rewriter's value gatherer and span scanners and the lockfile pruner
// alike, so "where does this string end" is answered once. Tracking quote
// state with a boolean toggle instead cannot see a multi-line string at all:
// three quotes toggle it back to "inside", so the scanner reads the string's
// contents as TOML and the delimiters as nothing.
func TOMLStringEnd(s string, i int) (end int, ok bool) {
	if i < 0 || i >= len(s) {
		return 0, false
	}
	quote := s[i]
	if quote != '"' && quote != '\'' {
		return 0, false
	}
	if IsMultilineStringOpener(s, i) {
		return multilineStringEnd(s, i)
	}
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			if quote == '"' {
				// A basic string's escape covers the next character, so an
				// escaped quote does not close it. A literal string has no
				// escapes, and its backslash is ordinary content.
				j++
			}
		case '\n':
			return 0, false
		case quote:
			return j + 1, true
		}
	}
	return 0, false
}

// multilineStringEnd returns the offset just past the closing delimiter of the
// multi-line TOML string whose opener sits at s[i].
//
// TOML lets one or two adjacent quote characters stand as content inside a
// multi-line string, so the terminator is a run of three to five of them and
// the delimiter is the last three of that run; a longer run has to be escaped
// and is malformed here. Inside the basic form a backslash escapes the
// character after it, so a run it introduces terminates nothing. ok is false
// when no terminator is found, which for a gatherer means the value carries
// on past the text it has read so far.
func multilineStringEnd(s string, i int) (end int, ok bool) {
	quote := s[i]
	for j := i + 3; j < len(s); {
		switch {
		case quote == '"' && s[j] == '\\':
			j += 2
		case s[j] != quote:
			j++
		default:
			run := 0
			for j+run < len(s) && s[j+run] == quote {
				run++
			}
			if run < 3 {
				j += run
				continue
			}
			if run > 5 {
				// Three or more adjacent quotes must be escaped; this is not
				// a string any TOML parser accepts.
				return 0, false
			}
			return j + run, true
		}
	}
	return 0, false
}

// SplitKeyPath splits a TOML key path into its dotted segments, unquoting
// quoted segments, so `tools."npm:lodash".version` yields
// [tools npm:lodash version]. It returns nil for anything that is not a
// well-formed key path. Both the mise.lock pruner and the config rewriter use
// it to interpret keys the same way mise's TOML parser does.
//
// A basic-string segment is decoded, not copied: TOML reads `"go"` as the
// key go, so returning the raw bytes would hide a declaration the parser in
// [Parse] does inventory, and the rewriter would then refuse a fix for a tool
// Deputy itself reported. An escape TOML does not define yields nil, because a
// key Deputy cannot read exactly as the parser does must not be matched
// approximately.
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
		case '"':
			decoded, next, ok := decodeBasicString(key, i)
			if !ok {
				return nil
			}
			seg, i = decoded, next
		case '\'':
			// Literal strings carry no escapes; the first quote ends them.
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

// UnquoteTOMLString decodes a quoted TOML string token to the text a TOML
// parser produces for it, so `"1.22.12"` reads as 1.22.12 and `'a\b'`
// keeps its backslash. All four of TOML's string forms are read, the two
// multi-line ones (opened by three double quotes or three apostrophes)
// included, because a config may spell a version with any of them and mise
// resolves them all the same way. A token that is not quoted, is unterminated,
// or carries an undefined escape is returned unchanged, leaving the caller
// comparing the text as written.
//
// Deputy compares declared version tokens against versions that came out of
// [Parse], which decoded them. Comparing an undecoded token against a decoded
// one silently fails to match, and a fix the config can take is reported as
// unrewritable, so both sides read the token the same way.
func UnquoteTOMLString(token string) string {
	if len(token) < 2 {
		return token
	}
	if IsMultilineStringOpener(token, 0) {
		return unquoteMultilineTOMLString(token)
	}
	switch token[0] {
	case '"':
		decoded, next, ok := decodeBasicString(token, 0)
		if !ok || next != len(token) {
			return token
		}
		return decoded
	case '\'':
		if token[len(token)-1] != '\'' {
			return token
		}
		if strings.IndexByte(token[1:len(token)-1], '\'') >= 0 {
			return token
		}
		return token[1 : len(token)-1]
	}
	return token
}

// IsMultilineStringOpener reports whether a TOML multi-line string opener,
// three identical quote characters, begins at s[i]. It is the one place that
// spells out what starts TOML's multi-line string forms, so the scanners that
// have to skip such a string and the decoder that has to read it agree on
// where one begins.
func IsMultilineStringOpener(s string, i int) bool {
	if i < 0 || i+2 >= len(s) {
		return false
	}
	q := s[i]
	return (q == '"' || q == '\'') && s[i+1] == q && s[i+2] == q
}

// unquoteMultilineTOMLString decodes a triple-quoted token by handing it back
// to the TOML parser, which is the only reading guaranteed to agree with the
// one behind [Parse]. The multi-line forms carry rules a second
// implementation would have to mirror exactly: a newline immediately after the
// opener is dropped, a backslash at the end of a line swallows the whitespace
// that follows it, and one or two adjacent quote characters are content rather
// than a terminator. Deriving the answer from the parser keeps those rules in
// one place instead of in a copy that drifts.
//
// The token is decoded on its own, and anything that decodes to more than the
// single value is refused, so text smuggled in after the closing delimiter
// cannot be read as if it were part of the version. A token the parser refuses
// is returned unchanged, matching how the single-line forms fail closed.
func unquoteMultilineTOMLString(token string) string {
	var decoded map[string]any
	if _, err := toml.Decode("v = "+token+"\n", &decoded); err != nil {
		return token
	}
	if len(decoded) != 1 {
		return token
	}
	value, ok := decoded["v"].(string)
	if !ok {
		return token
	}
	return value
}

// decodeBasicString reads the TOML basic string whose opening quote sits at
// index i, returning its decoded text and the offset just past the closing
// quote. ok is false when the string is unterminated or holds an escape TOML
// does not define, both of which the parser in [Parse] rejects outright.
//
// The escape set mirrors that parser rather than a hand-copied subset, so a
// key it accepts is one this reads and a key it refuses is one this refuses.
func decodeBasicString(s string, i int) (value string, next int, ok bool) {
	if i >= len(s) || s[i] != '"' {
		return "", 0, false
	}
	var b strings.Builder
	for j := i + 1; j < len(s); {
		switch c := s[j]; c {
		case '"':
			return b.String(), j + 1, true
		case '\\':
			decoded, after, escOK := decodeStringEscape(s, j)
			if !escOK {
				return "", 0, false
			}
			b.WriteString(decoded)
			j = after
		case '\n', '\r':
			// A basic string never spans lines; an unterminated one is not a
			// key path.
			return "", 0, false
		default:
			b.WriteByte(c)
			j++
		}
	}
	return "", 0, false
}

// decodeStringEscape decodes the TOML escape sequence beginning with the
// backslash at index i and returns the text it stands for plus the offset just
// past the sequence. ok is false for an undefined escape, a truncated one, or
// a code point that is not a valid scalar value.
func decodeStringEscape(s string, i int) (value string, next int, ok bool) {
	if i+1 >= len(s) {
		return "", 0, false
	}
	switch c := s[i+1]; c {
	case 'b':
		return "\b", i + 2, true
	case 't':
		return "\t", i + 2, true
	case 'n':
		return "\n", i + 2, true
	case 'f':
		return "\f", i + 2, true
	case 'r':
		return "\r", i + 2, true
	case 'e':
		return "\x1b", i + 2, true
	case '"':
		return `"`, i + 2, true
	case '\\':
		return `\`, i + 2, true
	case 'x', 'u', 'U':
		digits := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]
		end := i + 2 + digits
		if end > len(s) {
			return "", 0, false
		}
		r, err := strconv.ParseUint(s[i+2:end], 16, 32)
		if err != nil {
			return "", 0, false
		}
		if !utf8.ValidRune(rune(r)) {
			return "", 0, false
		}
		return string(rune(r)), end, true
	}
	return "", 0, false
}

// skipKeySpaces returns the first offset at or after i that is not a space or
// tab, for scanning TOML key paths.
func skipKeySpaces(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}
