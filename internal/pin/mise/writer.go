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

// scalarTrailRe matches the trivia allowed after a scalar value token: spaces
// and an optional comment running to the end of the text.
var scalarTrailRe = regexp.MustCompile(`^\s*(?:#.*)?$`)

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
	replace := func(value, pinned string, sole bool) (string, bool) {
		return replaceEntryVersion(value, currentVersions, pinned, sole)
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
		if !declaresVersion(spec.Versions, newVersion) {
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
			if declaresVersion(spec.Versions, current) {
				return false
			}
		}
		return true
	}
	return false
}

// declaresVersion reports whether a declaration's versions name the release
// want, comparing through [mise.SameVersion] so the two vocabularies that meet
// here agree: Deputy reports a Go runtime as "v1.24.3" while a mise config
// writes the release as mise installs it, and either side may be the one
// carrying the "v".
//
// A byte-for-byte comparison reads a config that already declares the target in
// the other spelling as never edited. The rewriter has already refused to
// overwrite that declaration, correctly, since it is not the version the finding
// describes, so the caller is told the fix could not be applied and stops before
// the work that is left: the stale sibling lock entry survives, lock resolution
// keeps serving the vulnerable version, and the next scan reports it against a
// config that no longer declares it.
func declaresVersion(versions []string, want string) bool {
	return slices.ContainsFunc(versions, func(v string) bool {
		return mise.SameVersion(v, want)
	})
}

// rewriteToolsTable walks a mise.toml-family config and applies replace to the
// value of every [tools] entry (or [tools.<tool>] version key) named in want,
// writing the file back only when something changed. It is the shared engine
// behind pinning (rewriteMiseVersions) and remediation (RewriteToolVersion);
// replace receives the raw value text after `=`, the pinned version, and
// whether this value is the tool's sole declaration, and reports the new value
// text and whether it changed. Entries in want that no replace call rewrote
// produce an error so callers never silently skip a tool.
func rewriteToolsTable(root *os.Root, relPath string, want map[string]string, replace func(value, pinned string, sole bool) (string, bool)) error {
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
	entries := arrayToolEntryCounts(lines)
	inRoot := true
	inTools := false
	toolTable := ""
	modified := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if header, isArray, ok := tomlHeader(trimmed); ok {
			// Track whether we're inside the [tools] table, or in a
			// [tools.<tool>] table where the version is a child key. Root
			// context ends at the first table header (TOML places all
			// root-level keys before it).
			//
			// A [[tools.<tool>]] entry declares that tool the same way, so it
			// sets the same context; a [[tools]] array is not a form mise
			// accepts, so its keys declare nothing here.
			inRoot = false
			inTools = !isArray && len(header) == 1 && header[0] == "tools"
			toolTable = ""
			if len(header) == 2 && header[0] == "tools" {
				toolTable = header[1]
			}
			continue
		}
		if (!inRoot && !inTools && toolTable == "") || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		eq, ok := tomlAssignmentIndex(line)
		if !ok {
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
			toolKey, _ = toolsTableKey(segs)
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

		// Gather the full logical value before rewriting anything: an array or
		// an inline table may span several lines, and treating only the first
		// line as the value corrupts the file (a bare `[` looks like a scalar
		// to the fallback path) or misses the fix entirely. Gathering for
		// every in-scope key also means continuation lines are skipped below
		// rather than being reparsed as declarations of their own.
		value := line[eq+1:]
		end := i
		for !tomlDelimitersBalanced(value) && end+1 < len(lines) {
			end++
			value += "\n" + lines[end]
		}
		if !tomlDelimitersBalanced(value) {
			// Unterminated array or table: malformed TOML, leave it alone.
			break
		}

		newValue := value
		var rewrote []string
		switch {
		case inlineTools:
			for name, pinned := range want {
				if nv, changed := replaceInlineToolValue(newValue, name, pinned, replace); changed {
					newValue = nv
					rewrote = append(rewrote, name)
				}
			}
		case toolKey != "":
			if pinned, ok := want[toolKey]; ok {
				if nv, changed := replace(value, pinned, entries[toolKey] <= 1); changed {
					newValue = nv
					rewrote = append(rewrote, toolKey)
				}
			}
		}
		if newValue != value {
			// The replacement only rewrites version tokens, so the line count
			// is preserved; splice the new lines back in place.
			repl := strings.Split(line[:eq+1]+newValue, "\n")
			if len(repl) == end-i+1 {
				copy(lines[i:end+1], repl)
				for _, name := range rewrote {
					applied[name] = true
				}
				modified = true
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

	return publishConfig(root, relPath, strings.Join(lines, "\n"), info.Mode().Perm())
}

// publishConfig writes the rewritten config back, replacing the file rather
// than truncating and refilling it in place. A config is a hand-written file
// Deputy was asked to edit, not one it can regenerate: truncating first means a
// full disk, a short write, or an interrupt leaves the manifest empty or
// half-parsed, the caller reports a failed fix, and the user's declarations are
// gone with no way to retry. A concurrent reader (mise itself, or an editor)
// sees the same empty window even when nothing fails.
//
// It is [mise.ReplaceFileAtomically], the same publication the sibling lockfile
// pruning uses, so both halves of one fix are equally safe to interrupt.
func publishConfig(root *os.Root, relPath, content string, perm os.FileMode) error {
	if err := mise.ReplaceFileAtomically(root, relPath, []byte(content), perm); err != nil {
		return fmt.Errorf("writing %s: %w", relPath, err)
	}
	return nil
}

// replaceVersionInValue replaces the version in a [tools] value (the text after
// `=`) with a quoted pinned version, for pinning: scalar values, inline tables,
// and single-version arrays are rewritten, while multi-version declarations are
// left for a manual pin. That is exactly replaceEntryVersion with no known
// vulnerable versions, so it delegates rather than duplicating the TOML value
// handling.
func replaceVersionInValue(value, pinned string, sole bool) (string, bool) {
	return replaceEntryVersion(value, nil, pinned, sole)
}

// replaceEntryVersion rewrites the version in one declaration of a tool. sole
// says the value is the whole declaration, which it is for every form but
// repeated [[tools.<tool>]] entries.
//
// Repeated entries are the line-oriented spelling of a multi-version array
// (mise 2026.7.3 lists both `[[tools.go]]` entries of a config as separate
// requests), so they take the array's rule: an entry is rewritten only when it
// names one of the versions the finding reports, and the licence a sole
// declaration has to rewrite a selector that could still resolve to a
// vulnerable version is withheld, because a sibling entry may be the request
// that selector meant. With no current version to pick an entry out, nothing
// is rewritten and the caller fails closed, rather than collapsing two
// requested toolchains into one version declared twice.
func replaceEntryVersion(value string, currents []string, pinned string, sole bool) (string, bool) {
	if !sole && !namesCurrentVersion(value, currents) {
		return value, false
	}
	return replaceVersionInValueTargeting(value, currents, pinned)
}

// namesCurrentVersion reports whether a declaration or array element spells one
// of the versions a finding reports, comparing through [mise.SameVersion] so
// the plan's spelling of a version ("v1.22.12") matches the config's. It is the
// one definition of "this is the declaration the finding is about" that both
// array elements and repeated tool entries are matched by.
func namesCurrentVersion(value string, currents []string) bool {
	return slices.ContainsFunc(elementVersions(value), func(v string) bool {
		return slices.ContainsFunc(currents, func(current string) bool {
			return mise.SameVersion(current, v)
		})
	})
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
// Currents are always consulted, at every arity. With several declared
// versions only the elements equal to one of currents are replaced, so the
// other pinned versions survive. A sole declaration (a scalar, or a
// one-element array) is additionally replaced when it is a selector that could
// still resolve to a current version, which matters because a config often
// declares a fuzzy version ("20") while the finding reports the resolved one
// ("20.11.0"); see selectorTargetsCurrent. Anything else changes nothing,
// letting the caller fail closed instead of guessing. The value may span
// multiple lines; only version tokens are rewritten, so line structure and
// comments survive.
func replaceVersionInValueTargeting(value string, currents []string, pinned string) (string, bool) {
	// Arrays first: element-wise, so an array value can never fall through to
	// the inline-table or scalar paths.
	if spans, ok := arrayElementSpans(value); ok {
		return replaceArrayElements(value, spans, currents, pinned)
	}

	// Inline table: replace only the version field, which may itself be an
	// array of versions (recursion handles that element-wise).
	if table, trailing, ok := splitInlineTable(value); ok {
		start, end, found := inlineTableVersionSpan(table)
		if !found {
			return value, false
		}
		sub, changed := replaceVersionInValueTargeting(table[start:end], currents, pinned)
		if !changed {
			return value, false
		}
		newValue := table[:start] + sub + table[end:] + trailing
		return newValue, newValue != value
	}

	// Scalar value (possibly with trailing comment).
	lead, token, trail, ok := splitScalarValue(value)
	if !ok {
		return value, false
	}
	if strings.Contains(token, "\n") {
		// A multi-line string spread over several lines cannot be swapped for
		// a single-line token: the caller splices the replacement back only
		// when the line count matches, and forcing it would leave the tail of
		// the string stranded as a bare line that no TOML parser will read.
		// Refuse, so the caller reports an unapplied update instead of
		// corrupting a config mise reads perfectly well.
		return value, false
	}
	if !selectorTargetsCurrent(unquoteKey(token), currents) {
		return value, false
	}
	newValue := lead + `"` + pinned + `"` + trail
	return newValue, newValue != value
}

// splitScalarValue splits a TOML scalar value (the text after `=`) into its
// leading whitespace, its value token, and the trailing whitespace and
// comment, so the token can be swapped while the layout around it survives.
//
// The token is read with [mise.TOMLStringEnd] rather than matched as a quote pair,
// because TOML has four string forms and mise resolves all of them: a
// quote-pair reading of `go = """1.22.12"""` sees an empty string followed by
// junk, so a fix the config can take is refused, and its multi-line spelling
// is read as a bare `"""` token whose replacement corrupts the file. ok is
// false when the text is not one scalar followed by nothing but trivia, which
// leaves the caller to fail closed.
func splitScalarValue(value string) (lead, token, trail string, ok bool) {
	start := skipTomlSpaces(value, 0)
	if start >= len(value) {
		return "", "", "", false
	}
	end := start
	if c := value[start]; c == '"' || c == '\'' {
		stringEnd, terminated := mise.TOMLStringEnd(value, start)
		if !terminated {
			return "", "", "", false
		}
		end = stringEnd
	} else {
		for end < len(value) && !isTomlSpace(value[end]) && value[end] != '#' {
			end++
		}
	}
	if end == start || !scalarTrailRe.MatchString(value[end:]) {
		return "", "", "", false
	}
	return value[:start], value[start:end], value[end:], true
}

// isTomlSpace reports whether c is whitespace between TOML tokens. Newlines
// count: mise accepts an array or inline table written across several lines.
func isTomlSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// selectorTargetsCurrent reports whether a sole declared version token may be
// rewritten to pinned, given the versions the finding says are vulnerable. It
// is what keeps an exact declaration from being rolled backwards: a plan built
// when the config said "1.22.12" must not overwrite a "1.25.1" that the user
// or another process has since committed, because the finding no longer
// describes what the file declares. Multi-version arrays already fail closed
// on a current-version mismatch, so sole declarations follow the same rule.
//
// Replacement is allowed when the declaration names a current version, when it
// is a partial selector that a current version satisfies ("20" or "20.11" for
// 20.11.0, "prefix:20" likewise), or when it names no version at all ("lts",
// "latest", "ref:main"), since mise resolves those at install time and they
// may well be resolving to the vulnerable version today. With no known current
// versions there is nothing to contradict, so the rewrite proceeds; that is
// the pinning path, which targets whatever is declared.
//
// Which of those a declaration is comes from [mise.DeclaredVersion], the same
// reading of mise's request grammar the rest of the package uses. Deciding it
// here on the token's first character would misread a vendor-prefixed exact
// release ("temurin-21.0.6+7") as a floating selector and let a stale plan
// downgrade an already-updated toolchain.
func selectorTargetsCurrent(declared string, currents []string) bool {
	if len(currents) == 0 {
		return true
	}
	version, constrained := mise.DeclaredVersion(declared)
	if !constrained {
		return true
	}
	return slices.ContainsFunc(currents, func(current string) bool {
		return mise.SelectorMatches(version, current)
	})
}

// replaceArrayElements rewrites the matching elements of a TOML array value,
// splicing replacements in by offset so element order, layout, and comments
// survive. Elements may be scalars, inline tables, or nested arrays; a
// structured element is rewritten by recursion, so an inline table keeps its
// tool options and a nested version array is edited element-wise in turn.
//
// An element is touched when one of the versions it declares, at any nesting
// depth, is a known vulnerable version. A one-element array declares the tool
// on its own, so it is additionally touched when its version is a selector
// that a current version satisfies, the same rule the scalar path applies (see
// selectorTargetsCurrent); an element declaring no version at all keeps the
// older unconditional behavior, since there is nothing to compare.
func replaceArrayElements(value string, spans [][2]int, currents []string, pinned string) (string, bool) {
	quoted := `"` + pinned + `"`
	sole := len(spans) == 1

	var b strings.Builder
	b.Grow(len(value) + len(spans)*(len(quoted)+2))
	last := 0
	changed := false
	for _, span := range spans {
		elem := value[span[0]:span[1]]
		if !namesCurrentVersion(elem, currents) &&
			!(sole && soleElementTargetsCurrent(elementVersions(elem), currents)) {
			continue
		}
		repl := quoted
		if _, isArray := arrayElementSpans(elem); isArray || isInlineTable(elem) {
			sub, ok := replaceVersionInValueTargeting(elem, currents, pinned)
			if !ok {
				continue
			}
			repl = sub
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

// soleElementTargetsCurrent reports whether the sole element of a
// single-element array may be rewritten. An element that declares no version
// has nothing to contradict the finding and stays replaceable; otherwise at
// least one of its declared versions must be a selector the finding's current
// versions satisfy.
func soleElementTargetsCurrent(versions, currents []string) bool {
	if len(versions) == 0 {
		return true
	}
	return slices.ContainsFunc(versions, func(v string) bool {
		return selectorTargetsCurrent(v, currents)
	})
}

// elementVersions returns every version an array element declares, flattening
// nesting: a scalar yields itself, an inline table yields the versions of its
// version field, and an array (including a version field that is itself an
// array) yields the versions of all its elements. Matching on the whole set is
// what lets a vulnerable version buried in a nested array select its element
// for rewriting; treating such an element as unmatchable would silently leave
// it in place while the command reported success. It returns nil when the
// element declares no version at all, which never matches.
func elementVersions(elem string) []string {
	if spans, ok := arrayElementSpans(elem); ok {
		var out []string
		for _, span := range spans {
			out = append(out, elementVersions(elem[span[0]:span[1]])...)
		}
		return out
	}
	if table, _, ok := splitInlineTable(elem); ok {
		start, end, found := inlineTableVersionSpan(table)
		if !found {
			return nil
		}
		return elementVersions(table[start:end])
	}
	valuePart, _ := splitTomlComment(elem)
	if v := strings.TrimSpace(valuePart); v != "" {
		return []string{unquoteKey(v)}
	}
	return nil
}

// isInlineTable reports whether a TOML value token is an inline table.
func isInlineTable(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), "{")
}

// splitInlineTable separates a leading inline-table value from the trivia that
// follows its closing brace, so a trailing comment survives a rewrite of the
// table's version field. ok is false when the value is not an inline table or
// its brace is never closed.
//
// The split is made at the closing brace, not at the first `#`: mise accepts an
// inline table written across several lines, and such a table may carry a
// comment of its own between two fields. Cutting there would hand the field
// scanner nothing but the opening line, and the rewriter would report that it
// could not rewrite a declaration that mise, and Deputy's own parser, read
// perfectly well.
func splitInlineTable(value string) (table, trailing string, ok bool) {
	i := skipTomlSpaces(value, 0)
	if i >= len(value) || value[i] != '{' {
		return "", "", false
	}
	end := tomlValueSpan(value, i)
	if end <= i || end > len(value) || value[end-1] != '}' {
		return "", "", false
	}
	return value[:end], value[end:], true
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
//
// An unterminated multi-line string counts as unbalanced for the same reason a
// dangling bracket does: the value runs on past the lines gathered so far, and
// stopping there would hand the scalar path a bare `"""` to overwrite. An
// unterminated single-line string cannot continue onto another line, so it is
// malformed rather than incomplete, and the text after it is left uncounted.
func tomlDelimitersBalanced(s string) bool {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\'':
			end, ok := mise.TOMLStringEnd(s, i)
			if !ok {
				return !mise.IsMultilineStringOpener(s, i) && depth <= 0
			}
			i = end - 1
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
// the key at the table's top level and applies replace to its value token;
// nested values it does not understand are skipped, leaving the caller to fail
// closed. The inline table is the [tools] table written inline, so a field is
// resolved to a tool by toolsTableKey, the same rule the table form uses: both
// `{ go = "1.22.12" }` and its dotted `{ go.version = "1.22.12" }` spelling
// declare go's version.
// A field of the root inline table is a whole declaration on its own: a TOML
// table cannot repeat a key, so the value is passed to replace as a sole one.
func replaceInlineToolValue(s, tool, pinned string, replace func(value, pinned string, sole bool) (string, bool)) (string, bool) {
	out, changed := s, false
	inlineTableFields(s, func(key []string, vstart, vend int) bool {
		if name, ok := toolsTableKey(key); !ok || name != tool {
			return true
		}
		if sub, ok := replace(s[vstart:vend], pinned, true); ok {
			out, changed = s[:vstart]+sub+s[vend:], true
		}
		return false
	})
	return out, changed
}

// inlineTableFields walks the top-level fields of a TOML inline table, calling
// visit with each field's key path and the [start, end) offsets of its value;
// visit returns false to stop. Nested tables and arrays are consumed as whole
// values, so visit only ever sees the table's own fields. Keys are read with
// TOML quoting rules, so a quoted spelling such as `"version"` is recognized
// exactly like the bare one, and split into path segments by mise.SplitKeyPath,
// the same splitter the line-oriented walker uses, so a dotted field key means
// the same thing wherever it is written. Whitespace includes newlines because
// mise accepts inline tables written across several lines.
func inlineTableFields(s string, visit func(key []string, vstart, vend int) bool) {
	i := skipTomlSpaces(s, 0)
	if i >= len(s) || s[i] != '{' {
		return
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
		case c == '}':
			return
		default:
			keyEnd, ok := tomlKeyPathEnd(s, i)
			if !ok {
				return
			}
			key := mise.SplitKeyPath(strings.TrimSpace(s[i:keyEnd]))
			if len(key) == 0 {
				return
			}
			j := skipTomlSpaces(s, keyEnd)
			if j >= len(s) || s[j] != '=' {
				return
			}
			vstart := skipTomlSpaces(s, j+1)
			vend := tomlValueSpan(s, vstart)
			if vend <= vstart {
				return
			}
			if !visit(key, vstart, vend) {
				return
			}
			i = vend
		}
	}
}

// tomlAssignmentIndex returns the index of the `=` separating a TOML key from
// its value on a single line. Quoted keys are skipped over, because mise tool
// keys carry option syntax that embeds an assignment
// (`"ubi:cli/cli[exe=gh]" = "1.0.0"`); splitting on the first `=` would cut the
// key in half and make the declaration unrewritable. ok is false when the line
// carries no top-level assignment.
func tomlAssignmentIndex(line string) (int, bool) {
	inSingle, inDouble, escaped := false, false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
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
			return 0, false
		case c == '=':
			return i, true
		}
	}
	return 0, false
}

// tomlKeyPathEnd returns the offset just past the TOML key path starting at i.
// A key may be a dotted path (`go.version`) and may quote any of its segments
// (`"go".version`), so the scan follows the path across dots instead of
// stopping at the first token; the segments themselves are read from the
// spanned text by mise.SplitKeyPath. ok is false when no key starts at i, a
// quoted segment is unterminated, or a dot ends the path.
func tomlKeyPathEnd(s string, i int) (end int, ok bool) {
	for {
		_, next, tokenOK := tomlKeyToken(s, i)
		if !tokenOK {
			return 0, false
		}
		i = next
		dot := skipTomlSpaces(s, i)
		if dot >= len(s) || s[dot] != '.' {
			return i, true
		}
		i = skipTomlSpaces(s, dot+1)
	}
}

// toolsTableKey resolves which tool a key path inside the [tools] table
// declares a version for. mise accepts both `go = "1.22.12"` and the dotted
// `go.version = "1.22.12"` spelling of the same declaration, and the root
// inline table (`tools = { ... }`) is that table written inline, so both forms
// must be recognized wherever the table appears. ok is false for any other
// path, which belongs to something the rewriter does not understand.
func toolsTableKey(key []string) (tool string, ok bool) {
	switch {
	case len(key) == 1:
		return key[0], true
	case len(key) == 2 && key[1] == "version":
		return key[0], true
	}
	return "", false
}

// tomlKeyToken reads the key token starting at i, returning its unquoted name
// and the offset just past it. Bare keys run to the first character that
// cannot appear in a key path (so a dotted key is returned whole); quoted keys
// are returned without their quotes. ok is false when no key token starts at i
// or a quoted key is unterminated.
func tomlKeyToken(s string, i int) (name string, end int, ok bool) {
	if i >= len(s) {
		return "", 0, false
	}
	if q := s[i]; q == '"' || q == '\'' {
		for j := i + 1; j < len(s); j++ {
			if q == '"' && s[j] == '\\' {
				j++
				continue
			}
			if s[j] == q {
				return s[i+1 : j], j + 1, true
			}
		}
		return "", 0, false
	}
	start := i
	for i < len(s) && isTomlKeyPathChar(s[i]) {
		i++
	}
	if i == start {
		return "", 0, false
	}
	return s[start:i], i, true
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
	for j := i; j < len(s); j++ {
		switch c := s[j]; {
		case c == '"' || c == '\'':
			// A delimiter inside a string closes nothing, so skip the whole
			// token. An unterminated one swallows the rest of the text.
			end, ok := mise.TOMLStringEnd(s, j)
			if !ok {
				return len(s)
			}
			j = end - 1
		case c == '#':
			// A comment runs to the end of the line; a brace or bracket inside
			// it closes nothing. The gatherer in tomlDelimitersBalanced already
			// skips comments, so a value it gathered whole would otherwise be
			// cut short here.
			for j < len(s) && s[j] != '\n' {
				j++
			}
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
// an inline table, returning its [start, end) offsets. Only a key at the
// table's own depth counts: a nested table may carry its own version key
// (`{ opts = { version = "meta" }, version = "1.22.12" }`) and mise reads the
// outer one, so matching the inner key would rewrite unrelated metadata and
// leave the vulnerable version in place. The span covers whole arrays and
// tables, so an array-valued version field is returned intact for element-wise
// rewriting rather than truncated into corrupt TOML.
func inlineTableVersionSpan(s string) (start, end int, ok bool) {
	inlineTableFields(s, func(key []string, vstart, vend int) bool {
		if len(key) != 1 || key[0] != "version" {
			return true
		}
		start, end, ok = vstart, vend, true
		return false
	})
	return start, end, ok
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
	switch s[i] {
	case '\'', '"':
		if end, ok := mise.TOMLStringEnd(s, i); ok {
			return end
		}
		// An unterminated string swallows the rest of the text; there is no
		// later token to find in it.
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

	return publishConfig(root, relPath, strings.Join(lines, "\n"), info.Mode().Perm())
}

// tomlHeader parses a TOML table header line into its key-path segments, with
// quoting resolved the same way assignments are parsed: `["tools".go]` yields
// ["tools", "go"], exactly as mise's own TOML parser reads it. Returning the
// raw text instead would make quoted spellings of the tools table invisible to
// the rewriter, which would then refuse a fix for a config it can parse.
//
// isArray reports the array-of-tables form, `[[tools.go]]`, which mise does
// accept: it reads the entry's version like any other declaration. A scanner
// that reads such a line as ordinary text does worse than miss it, since the
// table context of the previous header then leaks past the new header and the
// assignments below it are attributed to the wrong tool. ok is false for
// non-header lines.
func tomlHeader(line string) (segs []string, isArray bool, ok bool) {
	line, _ = splitTomlComment(line)
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "[") {
		return nil, false, false
	}
	open, closing := "[", "]"
	if strings.HasPrefix(line, "[[") {
		isArray, open, closing = true, "[[", "]]"
	}
	if len(line) < len(open)+len(closing) || !strings.HasSuffix(line, closing) {
		return nil, false, false
	}
	segs = mise.SplitKeyPath(line[len(open) : len(line)-len(closing)])
	if len(segs) == 0 {
		return nil, false, false
	}
	return segs, isArray, true
}

// arrayToolEntryCounts counts, per tool, the [[tools.<tool>]] entries a config
// declares. Repeating the header requests another version of the same tool, so
// the count is how the rewriter learns that a version assignment is one of
// several declarations rather than the whole of one, and has to be rewritten
// under the multi-version rule.
//
// The scan is over raw lines, so a header spelled inside a multi-line string
// is counted too. That can only overstate a declaration's arity, which makes
// the rewriter refuse an edit it might have made; understating it would let
// one entry's pin overwrite another's version.
func arrayToolEntryCounts(lines []string) map[string]int {
	counts := make(map[string]int)
	for _, line := range lines {
		header, isArray, ok := tomlHeader(line)
		if !ok || !isArray || len(header) != 2 || header[0] != "tools" {
			continue
		}
		counts[header[1]]++
	}
	return counts
}

// splitTomlComment cuts s at the `#` that begins a trailing comment, returning
// the text before it and the comment itself. A `#` inside a string is content,
// so strings are skipped whole rather than tracked with a quote toggle, which
// would read the body of a multi-line string as if it were TOML. An
// unterminated string leaves no comment to find.
func splitTomlComment(s string) (before, comment string) {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"' || c == '\'':
			end, ok := mise.TOMLStringEnd(s, i)
			if !ok {
				return s, ""
			}
			i = end - 1
		case c == '#':
			return s[:i], s[i:]
		}
	}
	return s, ""
}

// unquoteKey reads a quoted TOML token as the text a TOML parser produces for
// it, escapes and all. It defers to [mise.UnquoteTOMLString] so the version
// tokens compared here are read exactly as the parser behind mise.Parse read
// the versions they are compared against.
func unquoteKey(k string) string {
	return mise.UnquoteTOMLString(k)
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
