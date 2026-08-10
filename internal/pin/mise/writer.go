package mise

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/pin"
)

// scalarValueRe splits a scalar value (the text after `=`) into leading
// whitespace, the value token (a quoted or bare version), and any trailing
// whitespace/comment, so the token can be replaced while preserving layout.
var scalarValueRe = regexp.MustCompile(`^(\s*)("[^"]*"|'[^']*'|[^\s#]+)(\s*(?:#.*)?)$`)

// rewriteMiseVersions rewrites tool version values in a mise.toml [tools] table
// to the pinned exact versions, preserving comments, key quoting, and unrelated
// content. Only entries in the [tools] table are touched.
func rewriteMiseVersions(root *os.Root, relPath string, updates []pin.Update) error {
	if len(updates) == 0 {
		return nil
	}
	want := make(map[string]string, len(updates))
	for _, u := range updates {
		if err := validateMiseUpdate(u); err != nil {
			return err
		}
		want[u.Name] = u.PinnedValue
	}
	return rewriteToolsTable(root, relPath, want, replaceVersionInValue)
}

// RewriteToolVersion rewrites the declared version of a single tool in a
// mise.toml-family config, for remediation: Deputy edits the exact detected
// file in place instead of shelling out to `mise use`, which refuses untrusted
// configs, picks its own write target, and collapses multi-version arrays to a
// scalar. Formatting, comments, and unrelated entries are preserved. Arrays
// (single-line or multiline) are handled element-wise: every element equal to
// one of currentVersions is replaced and the other pinned versions survive; a
// multi-version array with no matching current version fails closed (an error
// naming the tool) rather than rewriting the wrong declaration.
// currentVersions may be empty when unknown, which still rewrites scalar and
// single-version declarations.
//
// The rewrite is idempotent: a config that already declares newVersion and
// none of currentVersions is reported as successfully rewritten rather than as
// an unapplied update. Callers do more than edit the config (remediation also
// prunes the sibling lockfile), and without this a failure in that later work
// would be unrecoverable: the config edit is already committed, so a retry
// would report "no tool entry applied" and stop before redoing the rest.
func RewriteToolVersion(root *os.Root, relPath, tool string, currentVersions []string, newVersion string) error {
	if err := validateMiseUpdate(pin.Update{Name: tool, PinnedValue: newVersion}); err != nil {
		return err
	}
	replace := func(value, pinned string) (string, bool) {
		return replaceVersionInValueTargeting(value, currentVersions, pinned)
	}
	err := rewriteToolsTable(root, relPath, map[string]string{tool: newVersion}, replace)
	if err == nil {
		return nil
	}
	if alreadyAtVersion(root, relPath, tool, currentVersions, newVersion) {
		return nil
	}
	return err
}

// alreadyAtVersion reports whether the config already declares tool at
// newVersion with none of currentVersions left, meaning an earlier run applied
// this exact edit. It parses the config the same way mise does, so every
// declaration form is recognized, and answers false on any read or parse
// failure so an unclear state is never mistaken for success.
func alreadyAtVersion(root *os.Root, relPath, tool string, currentVersions []string, newVersion string) bool {
	data, err := fs.ReadFile(root.FS(), relPath)
	if err != nil {
		return false
	}
	cfg, err := mise.Parse(relPath, data)
	if err != nil {
		return false
	}
	for _, spec := range cfg.Tools {
		if spec.Key != tool {
			continue
		}
		if !slices.Contains(spec.Versions, newVersion) {
			return false
		}
		if len(currentVersions) == 0 {
			// With no known vulnerable versions, only a lone declaration of
			// the new version is provably complete; any other version left
			// beside it may still be the vulnerable one.
			return len(spec.Versions) == 1
		}
		// Defensive: a vulnerable version left beside the new one means the
		// edit is incomplete. The rewriter would have replaced such an element,
		// so this guards against a partially written config rather than a
		// state the happy path can produce.
		for _, current := range currentVersions {
			if slices.Contains(spec.Versions, current) {
				return false
			}
		}
		return true
	}
	return false
}

// rewriteToolsTable walks a mise.toml-family config and applies replace to the
// value of every [tools] entry (or [tools.<tool>] version key) named in want,
// writing the file back only when something changed. It is the shared engine
// behind pinning (rewriteMiseVersions) and remediation (RewriteToolVersion);
// replace receives the raw value text after `=` and the pinned version, and
// reports the new value text and whether it changed. Entries in want that no
// replace call rewrote produce an error so callers never silently skip a tool.
func rewriteToolsTable(root *os.Root, relPath string, want map[string]string, replace func(value, pinned string) (string, bool)) error {
	applied := make(map[string]bool, len(want))

	rootFS := root.FS()
	info, err := fs.Stat(rootFS, relPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", relPath, err)
	}
	content, err := fs.ReadFile(rootFS, relPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", relPath, err)
	}

	lines := strings.Split(string(content), "\n")
	inRoot := true
	inTools := false
	toolTable := ""
	modified := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if header, ok := tomlHeader(trimmed); ok {
			// Track whether we're inside the [tools] table, or in a
			// [tools.<tool>] table where the version is a child key. Root
			// context ends at the first table header (TOML places all
			// root-level keys before it).
			inRoot = false
			inTools = header == "tools"
			toolTable = ""
			if key, ok := toolsSubtableKey(header); ok {
				toolTable = key
			}
			continue
		}
		if (!inRoot && !inTools && toolTable == "") || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		segs := mise.SplitKeyPath(strings.TrimSpace(line[:eq]))
		if len(segs) == 0 {
			continue
		}

		// Resolve which tool this key declares a version for, covering every
		// form mise's parser accepts: [tools] entries and their dotted
		// `<tool>.version` variant, `version` inside a [tools.<tool>] table,
		// root-level dotted keys (`tools.<tool>` / `tools.<tool>.version`),
		// and the root inline table (`tools = { ... }`).
		toolKey := ""
		inlineTools := false
		switch {
		case toolTable != "":
			if len(segs) == 1 && segs[0] == "version" {
				toolKey = toolTable
			}
		case inTools:
			switch {
			case len(segs) == 1:
				toolKey = segs[0]
			case len(segs) == 2 && segs[1] == "version":
				toolKey = segs[0]
			}
		default: // root context
			switch {
			case len(segs) == 1 && segs[0] == "tools":
				inlineTools = true
			case len(segs) == 2 && segs[0] == "tools":
				toolKey = segs[1]
			case len(segs) == 3 && segs[0] == "tools" && segs[2] == "version":
				toolKey = segs[1]
			}
		}

		if inlineTools {
			value := line[eq+1:]
			newValue := value
			for name, pinned := range want {
				if nv, changed := replaceInlineToolValue(newValue, name, pinned, replace); changed {
					newValue = nv
					applied[name] = true
				}
			}
			if newValue != value {
				lines[i] = line[:eq+1] + newValue
				modified = true
			}
			continue
		}

		// Gather the full logical value: a TOML array may span multiple
		// lines, and treating only the first line as the value corrupts the
		// file (a bare `[` looks like a scalar to the fallback path).
		value := line[eq+1:]
		end := i
		for !tomlDelimitersBalanced(value) && end+1 < len(lines) {
			end++
			value += "\n" + lines[end]
		}
		if !tomlDelimitersBalanced(value) {
			// Unterminated array: malformed TOML, leave the file untouched.
			break
		}

		pinned, ok := want[toolKey]
		if toolKey != "" && ok {
			newValue, changed := replace(value, pinned)
			if changed {
				// The replacement only rewrites version tokens, so the line
				// count is preserved; splice the new lines back in place.
				repl := strings.Split(line[:eq+1]+newValue, "\n")
				if len(repl) == end-i+1 {
					copy(lines[i:end+1], repl)
					applied[toolKey] = true
					modified = true
				}
			}
		}
		i = end
	}

	if err := unappliedUpdatesError(relPath, want, applied); err != nil {
		return err
	}

	if !modified {
		return nil
	}

	f, err := root.OpenFile(relPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("writing %s: %w", relPath, err)
	}
	_, writeErr := f.Write([]byte(strings.Join(lines, "\n")))
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	return writeErr
}

// replaceVersionInValue replaces the version in a [tools] value (the text after
// `=`) with a quoted pinned version, for pinning: scalar values, inline tables,
// and single-version arrays are rewritten, while multi-version declarations are
// left for a manual pin. That is exactly replaceVersionInValueTargeting with no
// known vulnerable versions, so it delegates rather than duplicating the TOML
// value handling.
func replaceVersionInValue(value, pinned string) (string, bool) {
	return replaceVersionInValueTargeting(value, nil, pinned)
}

// replaceVersionInValueTargeting rewrites the version(s) in a [tools] value
// (the text after `=`), preserving everything else about the declaration.
//
// It understands every value shape mise accepts, at any nesting depth: a
// scalar, an array of versions, an inline table with a version field, an array
// of inline tables, and an inline table whose version field is itself an
// array. Arrays are handled element-wise so a multi-version declaration never
// reaches the scalar path, which would replace the opening bracket and corrupt
// the file.
//
// Ambiguity decides whether currents are consulted: a single declared version
// (a scalar, or a one-element array) is unambiguous and is always replaced,
// which matters because a config often declares a fuzzy version ("20") while
// the finding reports the resolved one ("20.11.0"). With several declared
// versions only the elements equal to one of currents are replaced, so the
// other pinned versions survive and an unmatched declaration changes nothing,
// letting the caller fail closed instead of guessing. The value may span
// multiple lines; only version tokens are rewritten, so line structure and
// comments survive.
func replaceVersionInValueTargeting(value string, currents []string, pinned string) (string, bool) {
	// Arrays first: element-wise, so an array value can never fall through to
	// the inline-table or scalar paths.
	if spans, ok := arrayElementSpans(value); ok {
		return replaceArrayElements(value, spans, currents, pinned)
	}

	valuePart, comment := splitTomlComment(value)

	// Inline table: replace only the version field, which may itself be an
	// array of versions (recursion handles that element-wise).
	if strings.Contains(valuePart, "{") {
		start, end, ok := inlineTableVersionSpan(valuePart)
		if !ok {
			return value, false
		}
		sub, changed := replaceVersionInValueTargeting(valuePart[start:end], currents, pinned)
		if !changed {
			return value, false
		}
		newValue := valuePart[:start] + sub + valuePart[end:] + comment
		return newValue, newValue != value
	}

	// Scalar value (possibly with trailing comment).
	m := scalarValueRe.FindStringSubmatch(value)
	if m == nil {
		return value, false
	}
	newValue := m[1] + `"` + pinned + `"` + m[3]
	return newValue, newValue != value
}

// replaceArrayElements rewrites the matching elements of a TOML array value,
// splicing replacements in by offset so element order, layout, and comments
// survive. Elements may be scalars or inline tables; an inline-table element
// has only its version field rewritten so tool options are preserved. A
// one-element array is unambiguous and is replaced without consulting
// currents; otherwise only elements whose declared version matches one of
// currents are touched.
func replaceArrayElements(value string, spans [][2]int, currents []string, pinned string) (string, bool) {
	quoted := `"` + pinned + `"`
	unambiguous := len(spans) == 1

	var b strings.Builder
	b.Grow(len(value) + len(spans)*(len(quoted)+2))
	last := 0
	changed := false
	for _, span := range spans {
		elem := value[span[0]:span[1]]
		repl := quoted
		switch {
		case isInlineTable(elem):
			if !unambiguous {
				version, ok := elementVersion(elem)
				if !ok || !slices.Contains(currents, version) {
					continue
				}
			}
			sub, ok := replaceVersionInValueTargeting(elem, currents, pinned)
			if !ok {
				continue
			}
			repl = sub
		case !unambiguous && !slices.Contains(currents, unquoteKey(elem)):
			continue
		}
		b.WriteString(value[last:span[0]])
		b.WriteString(repl)
		last = span[1]
		changed = true
	}
	if !changed {
		return value, false
	}
	b.WriteString(value[last:])
	newValue := b.String()
	return newValue, newValue != value
}

// elementVersion returns the version an array element declares, for matching
// against known vulnerable versions: the token itself for a scalar element, or
// the version field for an inline-table element. ok is false when the element
// declares no single comparable version (no version field, or a nested array
// of versions), in which case the caller must not treat it as a match.
func elementVersion(elem string) (string, bool) {
	if !isInlineTable(elem) {
		return unquoteKey(elem), true
	}
	valuePart, _ := splitTomlComment(elem)
	start, end, ok := inlineTableVersionSpan(valuePart)
	if !ok {
		return "", false
	}
	inner := strings.TrimSpace(valuePart[start:end])
	if strings.HasPrefix(inner, "[") {
		return "", false
	}
	return unquoteKey(inner), true
}

// isInlineTable reports whether a TOML value token is an inline table.
func isInlineTable(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), "{")
}

// arrayElementSpans returns the [start, end) offsets of each element token in
// a TOML array value (the raw text after `=`, which may span multiple lines
// and contain comments). ok is false when the value is not an array or is
// malformed, in which case callers should fall back to non-array handling.
func arrayElementSpans(s string) (spans [][2]int, ok bool) {
	i := skipTomlSpaces(s, 0)
	if i >= len(s) || s[i] != '[' {
		return nil, false
	}
	i++
	for i < len(s) {
		switch c := s[i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',':
			i++
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == ']':
			return spans, true
		default:
			end := tomlValueSpan(s, i)
			if end <= i {
				return nil, false
			}
			spans = append(spans, [2]int{i, end})
			i = end
		}
	}
	// Unterminated array.
	return nil, false
}

// tomlDelimitersBalanced reports whether every array bracket and inline-table
// brace opened in a TOML value has been closed, ignoring delimiters inside
// strings and comments. The walker uses it to gather the continuation lines of
// a value that spans several lines into one logical value. Braces count
// because mise accepts inline tables written across multiple lines, and
// treating only the first line as the value would either corrupt the file or
// fail to apply a fix mise itself understands.
func tomlDelimitersBalanced(s string) bool {
	depth := 0
	inSingle, inDouble, escaped := false, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case inDouble && c == '\\':
			escaped = true
		case !inDouble && c == '\'':
			inSingle = !inSingle
		case !inSingle && c == '"':
			inDouble = !inDouble
		case inSingle || inDouble:
		case c == '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '[', c == '{':
			depth++
		case c == ']', c == '}':
			depth--
		}
	}
	return depth <= 0
}

// replaceInlineToolValue rewrites the value of one tool key inside a root
// `tools = { ... }` inline table, a form mise's parser accepts. It locates
// the key (bare or quoted) at the table's top level and applies replace to
// its value token; nested values it does not understand are skipped, leaving
// the caller to fail closed.
func replaceInlineToolValue(s, tool, pinned string, replace func(value, pinned string) (string, bool)) (string, bool) {
	depth := 0
	i := 0
	for i < len(s) {
		switch c := s[i]; {
		case c == ' ' || c == '\t' || c == ',':
			i++
		case c == '{':
			depth++
			i++
		case c == '}':
			depth--
			i++
		case c == '#':
			return s, false
		default:
			// A token: either a key (followed by `=`) or a bare value.
			var name string
			end := i
			if c == '"' || c == '\'' {
				end = tomlValueEnd(s, i)
				if end <= i+1 || s[end-1] != c {
					return s, false
				}
				name = s[i+1 : end-1]
			} else {
				for end < len(s) && isTomlKeyPathChar(s[end]) {
					end++
				}
				name = s[i:end]
			}
			if end == i {
				// Not a key-like token; skip a whole value.
				if end = tomlValueSpan(s, i); end <= i {
					return s, false
				}
				i = end
				continue
			}
			j := skipTomlSpaces(s, end)
			if j >= len(s) || s[j] != '=' {
				// A bare value token (e.g. an array element); move past it.
				i = end
				continue
			}
			vstart := skipTomlSpaces(s, j+1)
			vend := tomlValueSpan(s, vstart)
			if vend <= vstart {
				return s, false
			}
			if depth == 1 && name == tool {
				newSub, changed := replace(s[vstart:vend], pinned)
				if !changed {
					return s, false
				}
				return s[:vstart] + newSub + s[vend:], true
			}
			i = vend
		}
	}
	return s, false
}

// tomlValueSpan returns the end offset of the TOML value starting at i,
// spanning quoted strings, whole arrays, and whole inline tables (so nested
// structures are consumed as one token). Bare values end at the same
// delimiters as tomlValueEnd.
func tomlValueSpan(s string, i int) int {
	if i >= len(s) {
		return i
	}
	open := s[i]
	if open != '[' && open != '{' {
		return tomlValueEnd(s, i)
	}
	closing := byte(']')
	if open == '{' {
		closing = '}'
	}
	depth := 0
	inSingle, inDouble, escaped := false, false, false
	for j := i; j < len(s); j++ {
		c := s[j]
		switch {
		case escaped:
			escaped = false
		case inDouble && c == '\\':
			escaped = true
		case !inDouble && c == '\'':
			inSingle = !inSingle
		case !inSingle && c == '"':
			inDouble = !inDouble
		case inSingle || inDouble:
		case c == open:
			depth++
		case c == closing:
			depth--
			if depth == 0 {
				return j + 1
			}
		}
	}
	return len(s)
}

// inlineTableVersionSpan locates the value of the top-level `version` key in
// an inline table, returning its [start, end) offsets. The span covers whole
// arrays and nested tables (not just the text up to the next comma), so an
// array-valued version field is returned intact for element-wise rewriting
// rather than being truncated into corrupt TOML.
//
// Only a version key at the table's own depth counts. A nested table may carry
// its own version key (`{ opts = { version = "meta" }, version = "1.22.12" }`),
// and mise reads the outer one as the tool's version, so matching the inner key
// would rewrite unrelated metadata and leave the vulnerable version in place.
func inlineTableVersionSpan(s string) (start, end int, ok bool) {
	depth := 0
	inSingle := false
	inDouble := false
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			escaped = false
		case inDouble && c == '\\':
			escaped = true
		case !inDouble && c == '\'':
			inSingle = !inSingle
		case !inSingle && c == '"':
			inDouble = !inDouble
		case inSingle || inDouble:
		case c == '{':
			depth++
		case c == '}':
			depth--
		case depth == 1 && hasBareKeyAt(s, i, "version"):
			j := i + len("version")
			j = skipTomlSpaces(s, j)
			if j >= len(s) || s[j] != '=' {
				continue
			}
			j = skipTomlSpaces(s, j+1)
			end := tomlValueSpan(s, j)
			return j, end, end > j
		}
	}
	return 0, 0, false
}

func hasBareKeyAt(s string, i int, key string) bool {
	if !strings.HasPrefix(s[i:], key) {
		return false
	}
	beforeOK := i == 0 || !isTomlKeyPathChar(s[i-1])
	after := i + len(key)
	afterOK := after == len(s) || !isTomlKeyPathChar(s[after])
	return beforeOK && afterOK
}

func skipTomlSpaces(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

func tomlValueEnd(s string, i int) int {
	if i >= len(s) {
		return i
	}
	switch quote := s[i]; quote {
	case '\'', '"':
		escaped := false
		for j := i + 1; j < len(s); j++ {
			c := s[j]
			if escaped {
				escaped = false
				continue
			}
			if quote == '"' && c == '\\' {
				escaped = true
				continue
			}
			if c == quote {
				return j + 1
			}
		}
		return len(s)
	}
	for j := i; j < len(s); j++ {
		switch s[j] {
		case ' ', '\t', '\n', '\r', ',', '}', ']':
			return j
		}
	}
	return len(s)
}

func isTomlKeyPathChar(c byte) bool {
	return c == '.' || c == '_' || c == '-' ||
		'0' <= c && c <= '9' ||
		'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z'
}

// toolVersionsLineRe splits a .tool-versions line into leading whitespace, the
// tool name, the separator, the first version token, and the remainder (extra
// versions and/or a trailing comment).
var toolVersionsLineRe = regexp.MustCompile(`^(\s*)(\S+)(\s+)(\S+)(.*)$`)

// rewriteToolVersions rewrites tool versions in an asdf .tool-versions file to
// the pinned exact versions, preserving comments and layout. Lines declaring
// multiple versions for a tool are left untouched (the strategy skips them).
func rewriteToolVersions(root *os.Root, relPath string, updates []pin.Update) error {
	if len(updates) == 0 {
		return nil
	}
	want := make(map[string]string, len(updates))
	for _, u := range updates {
		if err := validateMiseUpdate(u); err != nil {
			return err
		}
		want[u.Name] = u.PinnedValue
	}
	applied := make(map[string]bool, len(want))

	rootFS := root.FS()
	info, err := fs.Stat(rootFS, relPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", relPath, err)
	}
	content, err := fs.ReadFile(rootFS, relPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", relPath, err)
	}

	lines := strings.Split(string(content), "\n")
	modified := false
	for i, line := range lines {
		m := toolVersionsLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pinned, ok := want[m[2]] // m[2] = tool name
		if !ok {
			continue
		}
		// Only rewrite single-version entries; a non-comment remainder means
		// multiple versions, which the strategy skips.
		if rest := strings.TrimSpace(m[5]); rest != "" && !strings.HasPrefix(rest, "#") {
			continue
		}
		newLine := m[1] + m[2] + m[3] + pinned + m[5]
		if newLine != line {
			lines[i] = newLine
			applied[m[2]] = true
			modified = true
		}
	}

	if err := unappliedUpdatesError(relPath, want, applied); err != nil {
		return err
	}

	if !modified {
		return nil
	}

	f, err := root.OpenFile(relPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("writing %s: %w", relPath, err)
	}
	_, writeErr := f.Write([]byte(strings.Join(lines, "\n")))
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	return writeErr
}

func tomlHeader(line string) (string, bool) {
	line, _ = splitTomlComment(line)
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "[") || strings.HasPrefix(line, "[[") || !strings.HasSuffix(line, "]") {
		return "", false
	}
	header := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
	return header, header != ""
}

func splitTomlComment(s string) (before, comment string) {
	inSingle := false
	inDouble := false
	escaped := false
	for i, r := range s {
		switch {
		case escaped:
			escaped = false
		case inDouble && r == '\\':
			escaped = true
		case !inDouble && r == '\'':
			inSingle = !inSingle
		case !inSingle && r == '"':
			inDouble = !inDouble
		case !inSingle && !inDouble && r == '#':
			return s[:i], s[i:]
		}
	}
	return s, ""
}

func toolsSubtableKey(header string) (string, bool) {
	rest, ok := strings.CutPrefix(header, "tools.")
	if !ok {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	if rest == "" || strings.Contains(rest, ".") && !strings.HasPrefix(rest, "\"") && !strings.HasPrefix(rest, "'") {
		return "", false
	}
	return unquoteKey(rest), true
}

// unquoteKey strips surrounding single or double quotes from a TOML key.
func unquoteKey(k string) string {
	if len(k) >= 2 {
		if (k[0] == '"' && k[len(k)-1] == '"') || (k[0] == '\'' && k[len(k)-1] == '\'') {
			return k[1 : len(k)-1]
		}
	}
	return k
}

func unappliedUpdatesError(relPath string, want map[string]string, applied map[string]bool) error {
	missing := make([]string, 0)
	for name := range want {
		if !applied[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	slices.Sort(missing)
	return fmt.Errorf("could not rewrite toolchain entries in %s: %s", relPath, strings.Join(missing, ", "))
}

// validateMiseUpdate ensures an Update carries a safe, exact pinned version.
func validateMiseUpdate(u pin.Update) error {
	if u.Name == "" {
		return fmt.Errorf("empty tool name in update")
	}
	if u.PinnedValue == "" {
		return fmt.Errorf("empty pinned value for %s", u.Name)
	}
	// Accept any concrete resolved version, including partial-but-final ones
	// (e.g. protobuf "33.1"); reject only channels/ranges.
	if !mise.IsConcreteVersion(u.PinnedValue) {
		return fmt.Errorf("pinned value %q for %s is not a concrete version", u.PinnedValue, u.Name)
	}
	if strings.ContainsAny(u.PinnedValue, "\n\r\"\\") {
		return fmt.Errorf("pinned value %q for %s contains invalid characters", u.PinnedValue, u.Name)
	}
	return nil
}
