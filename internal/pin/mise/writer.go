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

// singleArrayValueRe matches an array value with exactly one version token.
var singleArrayValueRe = regexp.MustCompile(`^(\s*\[\s*)("[^"]*"|'[^']*'|[^\s,\]]+)(\s*\]\s*(?:#.*)?)$`)

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
// are handled element-wise: the element equal to currentVersion is replaced
// and the other pinned versions survive; a multi-version array with no
// matching currentVersion fails closed (an error naming the tool) rather than
// rewriting the wrong declaration. currentVersion may be empty when unknown,
// which still rewrites scalar and single-version declarations.
func RewriteToolVersion(root *os.Root, relPath, tool, currentVersion, newVersion string) error {
	if err := validateMiseUpdate(pin.Update{Name: tool, PinnedValue: newVersion}); err != nil {
		return err
	}
	replace := func(value, pinned string) (string, bool) {
		return replaceVersionInValueTargeting(value, currentVersion, pinned)
	}
	return rewriteToolsTable(root, relPath, map[string]string{tool: newVersion}, replace)
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
	inTools := false
	toolTable := ""
	modified := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if header, ok := tomlHeader(trimmed); ok {
			// Track whether we're inside the [tools] table, or in a
			// [tools.<tool>] table where the version is a child key.
			inTools = header == "tools"
			toolTable = ""
			if key, ok := toolsSubtableKey(header); ok {
				toolTable = key
			}
			continue
		}
		if (!inTools && toolTable == "") || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := unquoteKey(strings.TrimSpace(line[:eq]))

		if toolTable != "" {
			if key != "version" {
				continue
			}
			pinned, ok := want[toolTable]
			if !ok {
				continue
			}
			newValue, changed := replace(line[eq+1:], pinned)
			if changed {
				lines[i] = line[:eq+1] + newValue
				applied[toolTable] = true
				modified = true
			}
			continue
		}

		pinned, ok := want[key]
		if !ok {
			continue
		}
		newValue, changed := replace(line[eq+1:], pinned)
		if changed {
			lines[i] = line[:eq+1] + newValue
			applied[key] = true
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

// replaceVersionInValue replaces the version in a [tools] value (the text after
// `=`) with a quoted pinned version. It handles scalar string/bare values and
// inline tables with a version field. Returns the new value text and whether a
// change was made.
func replaceVersionInValue(value, pinned string) (string, bool) {
	quoted := `"` + pinned + `"`

	// Inline table: replace only the version field.
	if strings.Contains(value, "{") {
		valuePart, comment := splitTomlComment(value)
		start, end, ok := inlineTableVersionValue(valuePart)
		if !ok {
			return value, false
		}
		var b strings.Builder
		b.Grow(len(valuePart) + len(comment) + len(pinned) + 2)
		b.WriteString(valuePart[:start])
		b.WriteString(quoted)
		b.WriteString(valuePart[end:])
		b.WriteString(comment)
		newValue := b.String()
		return newValue, newValue != value
	}

	// Single-version array. Multi-version arrays do not match and are left for
	// a manual pin.
	if m := singleArrayValueRe.FindStringSubmatch(value); m != nil {
		newValue := m[1] + quoted + m[3]
		return newValue, newValue != value
	}

	// Scalar value (possibly with trailing comment).
	m := scalarValueRe.FindStringSubmatch(value)
	if m == nil {
		return value, false
	}
	newValue := m[1] + quoted + m[3]
	return newValue, newValue != value
}

// replaceVersionInValueTargeting is replaceVersionInValue extended with
// element-wise array handling for remediation: in a multi-version array it
// replaces only the element equal to current, preserving the other pinned
// versions (the pin path skips such arrays entirely). Scalars, inline tables,
// and single-version arrays keep replaceVersionInValue semantics.
func replaceVersionInValueTargeting(value, current, pinned string) (string, bool) {
	valuePart, comment := splitTomlComment(value)
	spans, ok := arrayElementSpans(valuePart)
	if !ok {
		return replaceVersionInValue(value, pinned)
	}
	quoted := `"` + pinned + `"`

	// A single-version array is unambiguous: replace it like a scalar.
	if len(spans) == 1 {
		newValue := valuePart[:spans[0][0]] + quoted + valuePart[spans[0][1]:] + comment
		return newValue, newValue != value
	}

	// Multiple versions: only the element matching the known current version
	// may be replaced; anything else stays untouched so the caller fails
	// closed instead of guessing.
	if current == "" {
		return value, false
	}
	for _, span := range spans {
		if unquoteKey(valuePart[span[0]:span[1]]) != current {
			continue
		}
		newValue := valuePart[:span[0]] + quoted + valuePart[span[1]:] + comment
		return newValue, newValue != value
	}
	return value, false
}

// arrayElementSpans returns the [start, end) offsets of each element token in
// a TOML array value (the text after `=`, with any trailing comment already
// stripped). ok is false when the value is not an array or is malformed, in
// which case callers should fall back to non-array handling.
func arrayElementSpans(s string) (spans [][2]int, ok bool) {
	i := skipTomlSpaces(s, 0)
	if i >= len(s) || s[i] != '[' {
		return nil, false
	}
	i++
	for i < len(s) {
		i = skipTomlSpaces(s, i)
		if i >= len(s) {
			break
		}
		switch s[i] {
		case ']':
			return spans, true
		case ',':
			i++
		default:
			end := tomlValueEnd(s, i)
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

func inlineTableVersionValue(s string) (start, end int, ok bool) {
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
		case !inSingle && !inDouble && hasBareKeyAt(s, i, "version"):
			j := i + len("version")
			j = skipTomlSpaces(s, j)
			if j >= len(s) || s[j] != '=' {
				continue
			}
			j = skipTomlSpaces(s, j+1)
			end := tomlValueEnd(s, j)
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
		case ' ', '\t', ',', '}', ']':
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
