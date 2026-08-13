package policy

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// IssueSeverity says how loudly a validation issue should be reported. It maps
// onto LSP diagnostic severities and onto lint's pass/fail decision: errors and
// warnings fail a lint run, hints are advice.
type IssueSeverity int

const (
	// IssueError marks a bundle that cannot be loaded or a rule that cannot do
	// what it says.
	IssueError IssueSeverity = iota

	// IssueWarning marks a value Deputy does not recognize, so the surrounding
	// policy will not behave as written.
	IssueWarning

	// IssueHint marks authoring advice that does not change behavior.
	IssueHint
)

// String returns the lowercase label used in lint output.
func (s IssueSeverity) String() string {
	switch s {
	case IssueError:
		return "error"
	case IssueWarning:
		return "warning"
	case IssueHint:
		return "hint"
	default:
		return "unknown"
	}
}

// NoRule is the RuleIndex of an issue that is not scoped to a single rule.
const NoRule = -1

// Issue is one problem found while validating a policy bundle. Positions are
// 1-based as YAML reports them, and are zero when the issue cannot be tied to a
// specific node. Code is a stable identifier editors use to offer quick fixes.
type Issue struct {
	Policy    string        // Policy is the name of the offending policy, empty when unnamed or bundle-wide.
	RuleIndex int           // RuleIndex is the 0-based rule position, or NoRule.
	Line      int           // Line is the 1-based line of the offending node.
	Column    int           // Column is the 1-based column of the offending node.
	Length    int           // Length is the width of the offending token, 0 when unknown.
	Severity  IssueSeverity // Severity says how loudly to report the issue.
	Code      string        // Code is a stable machine-readable identifier.
	Message   string        // Message is the human-readable description.
}

// String renders the issue as "line:col: severity: policy rule: message" for
// command-line output. Callers prefix it with the file being linted. The
// location comes first so the line stays greppable and the message last so
// multi-line compiler output (a snippet with a caret) still reads correctly.
func (i Issue) String() string {
	var b strings.Builder
	if i.Line > 0 {
		fmt.Fprintf(&b, "%d:%d: ", i.Line, i.Column)
	}
	fmt.Fprintf(&b, "%s: ", i.Severity)
	switch {
	case i.Policy != "" && i.RuleIndex >= 0:
		fmt.Fprintf(&b, "policy %q rule[%d]: ", i.Policy, i.RuleIndex)
	case i.Policy != "":
		fmt.Fprintf(&b, "policy %q: ", i.Policy)
	case i.RuleIndex >= 0:
		fmt.Fprintf(&b, "rule[%d]: ", i.RuleIndex)
	}
	b.WriteString(i.Message)
	return b.String()
}

// RuleWhen describes a rule's `when` expression and the names in scope for it,
// so a caller can compile the expression with its own error rendering.
type RuleWhen struct {
	Policy       string   // Policy is the name of the policy that owns the rule.
	RuleIndex    int      // RuleIndex is the 0-based rule position.
	Expr         string   // Expr is the CEL source of the condition.
	Line         int      // Line is the 1-based line where the expression starts.
	Column       int      // Column is the 1-based column where the expression starts.
	DeclaredVars []string // DeclaredVars are the policy vars plus any caller-supplied extras.
}

// ValidateOptions tunes bundle validation for a particular surface.
type ValidateOptions struct {
	// Source names the bundle in messages that come from loading it, such as a
	// file path or a document URI. It defaults to "policy".
	Source string

	// ExtraVars are variable names the caller declares out of band, such as
	// lint's --var flag.
	ExtraVars []string

	// CheckWhen validates a rule condition. It is called in document order so
	// issues stay sorted by position. When nil, conditions are compiled with
	// Compile and reported with the raw compiler message; surfaces with richer
	// error rendering (the editor, the linter) supply their own.
	CheckWhen func(RuleWhen) []Issue
}

// LooksLikeStructuredBundle reports whether data has the shape of an authored
// policy bundle: a mapping carrying a "policies" key. It deliberately does not
// require the bundle to decode into Deputy's types, nor the key to hold a
// well-formed list, so a policy with a mistyped field or a "policies" mapping is
// still recognized as a policy and can be reported with located, specific errors
// instead of being dismissed as an unknown format. Compiled bundles are ruled
// out first: their JSON has a "policies" array too.
//
// A document whose "policies" key is not written directly still counts when a
// reader that resolves references finds one anyway, which a top-level merge key
// does. Without that fallback a bundle could inherit its whole policy list from
// an anchor and slip past the checks that key off this probe, the anchor refusal
// among them. The fallback asks the same question of the resolved document that
// the node walk asks of the written one, whether the key is there, so an
// inherited list that is empty or malformed is as much a bundle as an inherited
// list that is well formed.
//
// A document that does not parse as YAML has no nodes to probe, so the raw text
// is checked for the key instead. A syntax error is the mistake an author is
// most likely to make and the one they most need pointed at a line, and without
// this the file falls through to the unknown-format fallback while the editor,
// which validates the text directly, names the line.
func LooksLikeStructuredBundle(data []byte) bool {
	if IsCompiledBundle(data) {
		return false
	}
	root := &yaml.Node{}
	if err := yaml.Unmarshal(data, root); err != nil {
		return writesBundleKey(data)
	}
	if len(root.Content) == 0 {
		return false
	}
	// Key presence, not the value: `policies:` with nothing after it is a bundle
	// missing its list, which has to be reported as such rather than dismissed.
	if hasMappingKey(root.Content[0], bundlePoliciesKey) {
		return true
	}
	return resolvesToBundleKey(data)
}

// bundlePoliciesKey is the mapping key that marks a document as an authored
// policy bundle. bundleKeyMatchesStructTag pins it to the field the decoder
// reads, so the probe and the loader cannot drift apart.
const bundlePoliciesKey = "policies"

// unparsedBundleKey matches the bundle's policies key at the start of a line, in
// raw text. It is deliberately a last resort: YAML that parses is always probed
// by walking its nodes, and this runs only for a document the parser rejected
// outright, where no structure is available to walk.
var unparsedBundleKey = regexp.MustCompile(`^` + yamlKeyPattern(bundlePoliciesKey) + `[ \t]*:`)

// yamlKeyPattern returns a regexp fragment matching a YAML mapping key in each
// of the three ways a document can spell it: bare, single-quoted, and
// double-quoted. All three name the same key, so raw text that recognized only
// the bare form would dismiss a quoted bundle as an unknown format instead of
// reporting the syntax error the author needs pointed at a line. The key is
// escaped, so it is matched literally.
func yamlKeyPattern(key string) string {
	quoted := regexp.QuoteMeta(key)
	return `(?:` + quoted + `|'` + quoted + `'|"` + quoted + `")`
}

// writesBundleKey reports whether raw text writes the bundle's policies key at
// the top level, which is how a document the YAML parser rejected is still
// recognized as an authored bundle with a syntax error in it.
//
// A root key may be indented, as long as the whole document is: YAML fixes a
// mapping's indentation at its first key, so nothing above a root key is less
// indented than it. That is what tells an indented bundle apart from a nested
// policies key, and from the raw CEL where the same spelling is a map literal
// keyed inside an expression that started further left.
func writesBundleKey(data []byte) bool {
	rootIndent := -1
	for line := range strings.Lines(string(data)) {
		body := strings.TrimLeft(line, " \t")
		// A blank line carries no indentation, and a comment may sit at any, so
		// neither says where the document's keys begin.
		if strings.TrimSpace(body) == "" || strings.HasPrefix(body, "#") {
			continue
		}
		indent := len(line) - len(body)
		if rootIndent < 0 || indent < rootIndent {
			rootIndent = indent
		}
		if indent == rootIndent && unparsedBundleKey.MatchString(body) {
			return true
		}
	}
	return false
}

// hasMappingKey reports whether a YAML mapping node carries a key, whatever its
// value. MappingValue answers a different question, "what is this field set to",
// and reads an explicit null as unset; a probe asking whether the document is a
// bundle at all needs the key itself.
func hasMappingKey(mapNode *yaml.Node, key string) bool {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		k := mapNode.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return true
		}
	}
	return false
}

// resolvesToBundleKey reports whether data carries the bundle key once the
// references the node walk refuses to follow are resolved. It is how the shape
// probe sees a policies key the walk cannot: the decoder resolves the aliases and
// merge keys, so this answers "would a reader that resolves them find the key
// here" without any reader having to act on the resolved value.
//
// It decodes into a plain mapping rather than into Deputy's bundle types, and
// asks only whether the key is present, so the answer does not depend on the
// inherited value being a well-formed, non-empty policy list. Requiring that
// dismissed a bundle whose inherited list was empty or malformed as an unknown
// format, which withheld the refusal of the construct that supplied it and left
// the linter describing a different mistake than the editor.
func resolvesToBundleKey(data []byte) bool {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return false
	}
	_, ok := doc[bundlePoliciesKey]
	return ok
}

// ValidateBundle reports every structural problem in a structured policy bundle:
// unknown entrypoints, commands and actions, duplicate policy names, malformed
// rules, and conditions that do not compile. It is the one implementation behind
// both `deputy policy lint` and the editor's diagnostics, so a policy that lints
// clean is a policy the editor considers clean.
//
// It returns an error only when the text is not YAML at all, or is a compiled
// bundle rather than an authored one; every other problem comes back as an Issue
// so callers can report them all at once. A bundle that does not decode into
// Deputy's types is still validated: the node walk reports what it can locate
// and the decode failure is added on top.
//
// One run reports every independent defect, so an author fixes a file once
// rather than peeling errors one lint at a time. That is why each policy is
// walked and expanded on its own: nothing about one policy, and nothing the
// document does elsewhere, withholds the diagnostics for the rest.
func ValidateBundle(text string, opts ValidateOptions) ([]Issue, error) {
	if IsCompiledBundle([]byte(text)) {
		return nil, errors.New("compiled policy bundle: validate the authored policies it was built from")
	}
	root := &yaml.Node{}
	if err := yaml.Unmarshal([]byte(text), root); err != nil {
		return nil, fmt.Errorf("parse policy YAML: %w", err)
	}
	issues := make([]Issue, 0)
	if len(root.Content) == 0 {
		return issues, nil
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return append(issues, issueAt(doc, IssueError, "root-not-mapping", "root must be a mapping")), nil
	}
	// The refused constructs are reported before anything else reads the document,
	// so the rest of validation, and every other reader of a bundle, sees only
	// plain nodes. The scan comes before the policies lookup because a root merge
	// key can supply the whole list, which would otherwise read as a missing key.
	// It stops none of the checks that follow: a refused construct must not hide
	// an unrelated typo, or an uncompilable var, and cost the author a second lint
	// run. What a later check does skip is the node it cannot read, which is a
	// reference and not every node an anchor names (see resolvesElsewhere).
	issues = append(issues, refusedConstructIssues(root)...)
	source := cmp.Or(opts.Source, "policy")
	// What the policies list is wrong about, and what each policy it holds is
	// wrong about, are reported without returning, so the bundle-level backstop
	// below still runs. A list the walk cannot iterate says nothing about the
	// bundle metadata beside it, and returning here made the author fix the list
	// and lint again to be told about the rest.
	issues = append(issues, policiesListIssues(doc, source, opts)...)
	// Decoding the whole bundle is the last backstop, for the shapes that belong
	// to no single policy, such as bundle metadata of the wrong type. It stops at
	// its first failure, which is why it runs after every policy has been expanded
	// on its own and adds only what is not already reported. It is the decode
	// alone: routing it through the loader would stop at the loader's refusal of
	// an anchor this run has already located and named a line for, and hide the
	// bundle-level shape behind it.
	//
	// A document that says part of itself elsewhere is decoded too, references and
	// all. The decoder resolves what no reader of a bundle may, which is why
	// nothing here acts on the resolved value, but it is still the only reader that
	// can find these shapes, and an anchor is defined in the document it is used
	// in, so every line it names is a line the author wrote. Skipping it let one
	// alias withhold every bundle-level shape in the file until the alias was
	// removed and lint rerun.
	if _, _, err := decodeStructuredBundle([]byte(text), source, true); err != nil {
		issues = append(issues, backstopIssue(err, source, doc, issues)...)
	}
	return issues, nil
}

// policiesListIssues reports what the bundle's policies list is wrong about, and
// what each policy it holds is wrong about. It is everything ValidateBundle can
// say by walking the document, split out from the bundle-level decode so that
// neither withholds the other: a defect in the list itself is the one place a
// walk cannot go further, and it used to end the whole run.
func policiesListIssues(doc *yaml.Node, source string, opts ValidateOptions) []Issue {
	policiesNode := MappingValue(doc, bundlePoliciesKey)
	switch {
	case policiesNode == nil:
		// A root merge key supplies the whole list, so a document carrying one is
		// not missing it and the merge key is the only mistake to report. Nothing
		// else the document does can put the key here, so an anchor elsewhere does
		// not withhold this.
		if hasMergeKey(doc) {
			return nil
		}
		return []Issue{issueAt(doc, IssueError, "missing-policies", "missing required 'policies' list")}
	case policiesNode.Kind == yaml.AliasNode:
		// An aliased list is a list once resolved, so saying it is not one would
		// describe the alias rather than the mistake. The alias itself is already
		// reported as a refused construct.
		return nil
	case policiesNode.Kind != yaml.SequenceNode:
		// A value written directly is the mistake, whatever the document does
		// elsewhere.
		return []Issue{issueAt(policiesNode, IssueError, "policies-not-list", "'policies' must be a list")}
	case len(policiesNode.Content) == 0:
		// An empty list is reported here rather than left to the loader backstop,
		// so the diagnostic names the line the author has to fill in.
		return []Issue{issueAt(policiesNode, IssueError, "empty-policies", "'policies' must contain at least one policy")}
	}
	var issues []Issue
	seenNames := map[string]struct{}{}
	for _, item := range policiesNode.Content {
		// Skip a policy the walk cannot read: an alias or a merge key beneath it
		// puts part of the policy somewhere else, so every further message would
		// describe the reference rather than the policy the author meant. Both are
		// already reported. An anchor definition is not a reference, so a policy
		// carrying one says what it says and is checked like any other.
		if resolvesElsewhere(item) {
			continue
		}
		if item.Kind != yaml.MappingNode {
			issues = append(issues, issueAt(item, IssueError, "policy-not-mapping", "policy must be a mapping"))
			continue
		}
		located := validatePolicyNode(item, seenNames, opts)
		issues = append(issues, located...)
		issues = append(issues, expandedPolicyIssues(item, source, opts.ExtraVars, located)...)
	}
	return issues
}

// expandedPolicyIssues reports what only expanding one policy can find. Two
// defects hide from the node walk: a field whose type the walk does not model,
// such as a rule status written as a string, and the CEL a policy generates,
// since a policy's vars wrap every condition in a comprehension that no per-rule
// check compiles. Expanding here is what makes a bundle that lints clean a
// bundle `deputy policy bundle` can compile.
//
// It works from the policy's own node rather than from a load of the whole
// bundle, which is what lets one pass report every policy. A bundle-wide load
// stops at its first failure, so one policy's mistyped field, or an anchor
// written anywhere in the document, used to withhold the diagnostics for every
// other policy and cost the author a lint run per defect.
//
// Within one policy the same rule holds, which is why the vars are compiled
// first and on their own: every step after them stops at its first failure, so
// asking about them last is asking only about the policies nothing else is wrong
// with. Whatever the vars answer is independent of the field the decoder refuses
// and of the entrypoint the walk does not recognize, and an author who has to
// fix one before being told about the other pays a lint run per defect.
//
// located is what the walk already reported for this policy, so a failure that
// restates one of those is dropped and a single mistake stays a single issue.
func expandedPolicyIssues(item *yaml.Node, source string, extraVars []string, located []Issue) []Issue {
	var pol structuredPolicy
	// Decoding resolves aliases and merge keys, which the format refuses; that is
	// safe here because a policy carrying one anywhere beneath it never reaches
	// this point, so the decoder reads only what the policy itself writes. A field
	// the decoder refuses leaves the rest of the policy decoded, so the vars are
	// still worth asking about.
	decodeErr := item.Decode(&pol)
	pol.Name = strings.TrimSpace(pol.Name)
	issues := varCompileIssues(pol, item, source, extraVars, located)
	if decodeErr != nil {
		return append(issues, backstopIssue(fmt.Errorf("%s: %w", source, decodeErr), source, item, located)...)
	}
	// Expanding the policy whole would stop at, or restate in generated CEL the
	// author never wrote, a defect that is already reported: an uncompilable var
	// wraps every condition, and a located error is the mistake itself.
	if len(issues) > 0 || slices.ContainsFunc(located, func(is Issue) bool { return is.Severity == IssueError }) {
		return issues
	}
	body, err := pol.toCELSource()
	if err != nil {
		return backstopIssue(fmt.Errorf("%s/%s: %w", source, pol.Name, err), source, item, located)
	}
	if err := Compile(body, extraVars); err != nil {
		issue := issueAt(item, IssueError, "cel-error", err.Error())
		issue.Policy = pol.Name
		return []Issue{issue}
	}
	return nil
}

// varCompileIssues reports the vars of one policy that do not compile. Wrapping
// an empty body in them asks about the vars and nothing else, which is the one
// question every other step of the expansion can stop short of: it compiles the
// generated CEL only once the whole policy has decoded and expanded, so a rule
// the walk has already reported, an entrypoint it does not recognize, or a field
// the decoder refuses would each hide an uncompilable var behind them.
//
// It reports only what nothing else owns, which is what located is for: a var
// name that is empty or duplicated is located by the walk, so the wrapping
// failure that restates it is folded rather than printed twice. Discarding that
// failure outright is not the same thing. It withheld any var-shape defect the
// walk does not model, and left the one it does to a bundle-wide backstop that an
// unrelated located error stops before it runs.
//
// A name the policy cannot bind is reported and then set aside, so the vars
// beneath it are still compiled. It is the defect of one var, and stopping at it
// asked about the vars only in a policy whose every name is already right, which
// cost the author a lint run per mistyped name. Setting one aside is not
// forgiving it: the name is reported here, the walk locates it as an error of its
// own, and every reader that runs the policy refuses it outright.
//
// The expression such a var holds is still asked about too, in the scope it would
// have been evaluated in, which is the vars bound above it. A name that binds
// nothing says nothing about the expression beside it, and withholding it made the
// author fix the name to be told the value was wrong as well.
func varCompileIssues(pol structuredPolicy, item *yaml.Node, source string, extraVars []string, located []Issue) []Issue {
	if len(pol.Vars) == 0 {
		return nil
	}
	var (
		issues []Issue
		bound  orderedVars
	)
	// backstop renders a failure of the expansion as an issue folded against what
	// the walk already located, which is where a var holding a value with no CEL
	// spelling is named on its own line (see validateVars).
	backstop := func(err error) []Issue {
		return backstopIssue(fmt.Errorf("%s/%s: %w", source, pol.Name, err), source, item, located)
	}
	// nested asks what wrapping a body in vars finds: a var Deputy cannot write into
	// the generated CEL at all, or generated CEL that does not compile.
	nested := func(vars orderedVars, body string) []Issue {
		expr, err := nestVars(vars, body)
		if err != nil {
			return backstop(err)
		}
		return celIssues(expr, extraVars, item, pol.Name)
	}
	for _, binding := range pol.Vars.bindings() {
		if binding.err == nil {
			bound = append(bound, binding.kv)
			continue
		}
		issues = append(issues, backstop(binding.err)...)
		expr, err := binding.kv.exprString()
		if err != nil {
			issues = append(issues, backstop(err)...)
			continue
		}
		issues = append(issues, nested(binding.scope, expr)...)
	}
	// The vars that do bind are compiled as one nest, since each is in scope for
	// the next, and wrapping an empty body asks about them and nothing else.
	return append(issues, nested(bound, "[]")...)
}

// celIssues reports generated CEL that does not compile as an issue anchored on the
// policy node. It is the one place validation renders a compiler failure over CEL
// the author did not write, so the vars a policy binds and the expression of one it
// cannot bind are reported the same way.
func celIssues(body string, extraVars []string, item *yaml.Node, policyName string) []Issue {
	err := Compile(body, extraVars)
	if err == nil {
		return nil
	}
	issue := issueAt(item, IssueError, "cel-error", err.Error())
	issue.Policy = policyName
	return []Issue{issue}
}

// backstopIssue renders a load failure as an issue, or nothing when a located
// issue already describes the same defect. It is anchored on the line the
// failure names, since the decoder names one for a field the walk does not
// model, and otherwise on the node the failure came from.
func backstopIssue(err error, source string, node *yaml.Node, located []Issue) []Issue {
	message, duplicate := loaderMessage(err, source, located)
	if duplicate {
		return nil
	}
	issue := Issue{
		RuleIndex: NoRule,
		Line:      lineFromYAMLError(message),
		Column:    1,
		Severity:  IssueWarning,
		Code:      "bundle-error",
		Message:   message,
	}
	if issue.Line == 0 && node != nil {
		issue.Line, issue.Column = node.Line, node.Column
	}
	return []Issue{issue}
}

// validatePolicyNode checks one policy mapping: its name uniqueness, its
// entrypoint and command vocabularies, and its rules. seenNames accumulates
// across the bundle so duplicates are reported on the second occurrence.
func validatePolicyNode(item *yaml.Node, seenNames map[string]struct{}, opts ValidateOptions) []Issue {
	var issues []Issue
	name := ""
	nameNode := MappingValue(item, "name")
	if nameNode != nil && nameNode.Kind == yaml.ScalarNode {
		name = strings.TrimSpace(nameNode.Value)
		if name != "" {
			if _, dup := seenNames[name]; dup {
				issues = append(issues, issueAt(nameNode, IssueError, "duplicate-policy", fmt.Sprintf("duplicate policy name %q", name)))
			}
			seenNames[name] = struct{}{}
		}
	}
	issues = append(issues, validateListEnum(item, "entrypoints", IsAllowedEntrypoint)...)
	issues = append(issues, validateListEnum(item, "commands", IsAllowedCommand)...)
	issues = append(issues, validateMode(item)...)
	issues = append(issues, validateVars(item)...)

	declaredVars := DeclaredVarNames(item)
	issues = append(issues, validateRules(item, name, append(declaredVars, opts.ExtraVars...), opts.CheckWhen)...)
	for i := range issues {
		if issues[i].Policy == "" {
			issues[i].Policy = name
		}
	}
	return issues
}

// validateMode checks a policy's execution mode against the known vocabulary and
// anchors the report on the mode node, so it is reported in the same pass as
// every other defect rather than only once the loader gets that far.
func validateMode(item *yaml.Node) []Issue {
	node := MappingValue(item, "mode")
	if node == nil {
		return nil
	}
	if node.Kind != yaml.ScalarNode {
		return []Issue{issueAt(node, IssueError, "mode-not-string", "'mode' must be a string")}
	}
	if strings.TrimSpace(node.Value) == "" {
		return nil
	}
	if _, err := ValidateMode(node.Value); err != nil {
		issue := issueAt(node, IssueError, "invalid-mode", err.Error())
		issue.Length = len(node.Value)
		return []Issue{issue}
	}
	return nil
}

// varKeyName returns the name a vars key binds, read the way the decoder reads
// it, or the empty string when it binds none. A null key is the case the two
// readers would otherwise disagree about: the decoder leaves the name at its zero
// value, which every reader of a bundle refuses, while `null` and `~` are text a
// walk over the document would take for a name.
//
// It is the key-position counterpart of MappingValue reading a null value as
// unset, and it is what lets rewritesItsText go on exempting null: the exemption
// holds only because both readers model null the same way, which in key position
// they now do.
func varKeyName(key *yaml.Node) string {
	if key == nil || key.Kind != yaml.ScalarNode || isNullNode(key) {
		return ""
	}
	return normalizeVarName(key.Value)
}

// validateVars checks the vars mapping: it must be a mapping, every variable
// needs a unique non-empty name, since duplicates silently shadow each other
// when the policy is expanded, and every value has to have a CEL spelling.
func validateVars(item *yaml.Node) []Issue {
	node := MappingValue(item, "vars")
	if node == nil {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return []Issue{issueAt(node, IssueError, "vars-not-mapping", "'vars' must be a mapping")}
	}
	var issues []Issue
	seen := map[string]struct{}{}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key := node.Content[i]
		name := varKeyName(key)
		switch {
		case name == "":
			issues = append(issues, issueAt(key, IssueError, "empty-var-name", emptyVarNameMessage))
		default:
			if _, dup := seen[name]; dup {
				issues = append(issues, issueAt(key, IssueError, "duplicate-var", fmt.Sprintf(duplicateVarNameFormat, name)))
			}
			seen[name] = struct{}{}
		}
		// The value is asked about whatever the name above it says, since a name
		// that binds nothing says nothing about the value beside it. Stopping at
		// the name reported the value as the expansion's unlocated backstop
		// instead, so one mistake changed severity and line depending on an
		// unrelated one.
		issues = append(issues, varValueIssues(name, node.Content[i+1])...)
	}
	return issues
}

// varValueIssues reports a var holding a value Deputy cannot write into the CEL a
// policy generates. A non-string value is marshaled to JSON when the policy is
// expanded, and YAML writes values JSON has no spelling for, a not-a-number and
// the infinities among them, so a var holding one cannot be expanded at all.
//
// It asks encoding/json rather than judging the value itself, and it reads string
// against non-string the way the decoder does, so it recognizes exactly what the
// expansion recognizes: a string is the author's own CEL and goes in as written,
// which is why it is not asked about here.
//
// Locating it here is what reports it on the line it is written on and beside the
// policy's other defects. The expansion stops at the first var it cannot write, so
// on its own it named one value per lint run and anchored it on the policy.
func varValueIssues(name string, value *yaml.Node) []Issue {
	if value == nil || (value.Kind == yaml.ScalarNode && value.Tag == strTag) {
		return nil
	}
	var decoded any
	// A value the decoder cannot read at all is the decoder's to report, on the
	// line it names; this asks only about the values it can read.
	if err := value.Decode(&decoded); err != nil {
		return nil
	}
	if _, err := json.Marshal(decoded); err != nil {
		return []Issue{issueAt(value, IssueError, "var-not-representable", varNotRepresentableError(name, err).Error())}
	}
	return nil
}

// validateListEnum checks that every entry of a string-list field belongs to a
// closed vocabulary. An unknown entry is a warning rather than an error because
// the bundle still loads: the policy just never matches what the author meant.
func validateListEnum(item *yaml.Node, key string, allowed func(string) bool) []Issue {
	node := MappingValue(item, key)
	if node == nil {
		return nil
	}
	if node.Kind != yaml.SequenceNode {
		return []Issue{issueAt(node, IssueError, key+"-not-list", fmt.Sprintf("'%s' must be a list", key))}
	}
	singular := strings.TrimSuffix(key, "s")
	var issues []Issue
	for _, v := range node.Content {
		if v.Kind != yaml.ScalarNode {
			issues = append(issues, issueAt(v, IssueError, key+"-not-strings", fmt.Sprintf("'%s' items must be strings", key)))
			continue
		}
		if !allowed(v.Value) {
			issues = append(issues, issueAt(v, IssueWarning, "invalid-"+singular, fmt.Sprintf("invalid %s %q", singular, v.Value)))
		}
	}
	return issues
}

// validateRules checks the rules list of a policy: every rule needs a condition
// that compiles and an action from the known vocabulary, and a rule that denies
// or warns should say why.
func validateRules(item *yaml.Node, policyName string, declaredVars []string, checkWhen func(RuleWhen) []Issue) []Issue {
	rulesNode := MappingValue(item, "rules")
	if rulesNode == nil {
		return []Issue{issueAt(item, IssueError, "missing-rules", "policy missing 'rules'")}
	}
	if rulesNode.Kind != yaml.SequenceNode {
		return []Issue{issueAt(rulesNode, IssueError, "rules-not-list", "'rules' must be a list")}
	}
	if len(rulesNode.Content) == 0 {
		return []Issue{issueAt(rulesNode, IssueError, "empty-rules", policyNeedsRuleMessage)}
	}
	var issues []Issue
	for idx, rule := range rulesNode.Content {
		if rule.Kind != yaml.MappingNode {
			issues = append(issues, ruleIssue(idx, issueAt(rule, IssueError, "rule-not-mapping", "rule must be a mapping")))
			continue
		}
		// A rule's condition and its action are independent fields, so a missing
		// condition must not hide a bad action: only the compile step is skipped,
		// since there is nothing to compile.
		whenNode := MappingValue(rule, "when")
		if whenNode == nil || whenNode.Kind != yaml.ScalarNode {
			issues = append(issues, ruleIssue(idx, issueAt(rule, IssueError, "missing-when", "rule missing 'when' expression")))
		} else {
			for _, issue := range checkRuleWhen(checkWhen, RuleWhen{
				Policy:       policyName,
				RuleIndex:    idx,
				Expr:         whenNode.Value,
				Line:         whenNode.Line,
				Column:       whenNode.Column,
				DeclaredVars: declaredVars,
			}) {
				issues = append(issues, ruleIssue(idx, issue))
			}
		}
		issues = append(issues, validateRuleAction(rule, idx)...)
		issues = append(issues, validateRuleDetails(rule, idx)...)
	}
	return issues
}

// validateRuleDetails reports a rule's details that Deputy cannot put into the
// action the policy generates. The details are marshaled to JSON when a rule is
// expanded, and YAML writes values JSON has no spelling for, a NaN or an infinity
// among them, so a rule carrying one cannot be expanded at all.
//
// It asks encoding/json rather than judging the value itself, so it recognizes
// exactly what the expansion recognizes. Locating it here is what reports it on
// the line it is written on and beside the rule's other defects: the expansion
// refuses a field of the rule in a fixed order and stops, so an action typo above
// the details used to withhold this until the typo was fixed and lint rerun.
func validateRuleDetails(rule *yaml.Node, idx int) []Issue {
	node := MappingValue(rule, "details")
	if node == nil {
		return nil
	}
	var details map[string]any
	// A details value the decoder cannot read at all is the decoder's to report,
	// on the line it names; this asks only about the values it can read.
	if err := node.Decode(&details); err != nil {
		return nil
	}
	if _, err := json.Marshal(details); err != nil {
		message := fmt.Sprintf("'details' holds a value that cannot be represented: %v", err)
		return []Issue{ruleIssue(idx, issueAt(node, IssueError, "details-not-representable", message))}
	}
	return nil
}

// validateRuleAction checks a rule's action against the allow/deny/warn
// vocabulary and nudges deny/warn rules to carry a reason.
func validateRuleAction(rule *yaml.Node, idx int) []Issue {
	actionNode := MappingValue(rule, "action")
	if actionNode == nil || actionNode.Kind != yaml.ScalarNode {
		return []Issue{ruleIssue(idx, issueAt(rule, IssueError, "missing-action", "rule missing 'action'"))}
	}
	action, err := ValidateActionType(actionNode.Value)
	if err != nil {
		issue := issueAt(actionNode, IssueError, "invalid-action", err.Error())
		issue.Length = len(actionNode.Value)
		return []Issue{ruleIssue(idx, issue)}
	}
	if action != ActionDeny && action != ActionWarn {
		return nil
	}
	reasonNode := MappingValue(rule, "reason")
	if reasonNode != nil && strings.TrimSpace(reasonNode.Value) != "" {
		return nil
	}
	issue := issueAt(actionNode, IssueHint, "missing-reason", "missing 'reason' for warn/deny")
	issue.Length = len(actionNode.Value)
	return []Issue{ruleIssue(idx, issue)}
}

// checkRuleWhen runs the caller's condition check, falling back to a plain
// Compile so every surface validates conditions even without custom rendering.
func checkRuleWhen(checkWhen func(RuleWhen) []Issue, when RuleWhen) []Issue {
	if checkWhen != nil {
		return checkWhen(when)
	}
	if err := Compile(when.Expr, when.DeclaredVars); err != nil {
		return []Issue{{
			RuleIndex: when.RuleIndex,
			Line:      when.Line,
			Column:    when.Column,
			Severity:  IssueError,
			Code:      "cel-error",
			Message:   err.Error(),
		}}
	}
	return nil
}

// loaderMessage prepares the loader's failure for reporting and says whether a
// located issue already covers it. The loader prefixes its message with the
// source and policy ("bundle.yaml/name: rule[0]: ..."), so comparison strips
// that prefix and then treats the remainder as a duplicate when it and a located
// message contain one another: the two describe the same defect in slightly
// different words. Anything else is a shape the node walk does not model and is
// reported as is.
//
// Containment alone is not enough for the defects the two readers name in
// different vocabularies, so a rule shape the walk located also covers the
// loader's refusal of a policy with no rules to run.
func loaderMessage(err error, source string, located []Issue) (string, bool) {
	message, ok := unlocatedDecodeMessage(err, located)
	if !ok {
		return "", true
	}
	detail := strings.TrimPrefix(message, source+"/")
	if _, rest, ok := strings.Cut(detail, ": "); ok {
		detail = rest
	}
	if rest, ok := strings.CutPrefix(detail, "rule["); ok {
		if _, tail, found := strings.Cut(rest, "]: "); found {
			detail = tail
		}
	}
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return message, false
	}
	for _, issue := range located {
		if issue.Severity == IssueHint {
			continue
		}
		if strings.Contains(issue.Message, detail) || strings.Contains(detail, issue.Message) {
			return message, true
		}
		if _, shape := valueShapeTypes[issue.Code]; detail == policyNeedsRuleMessage && shape {
			return message, true
		}
	}
	return message, false
}

// valueShapeTypes maps each code the node walk reports for a value that is not
// the shape a bundle needs, a policies list that is not a list, an entry of it
// that is not a policy, and rules the walk cannot read as a list of rules, to the
// Go type the decoder names when it refuses the same value. Every reader of a
// bundle refuses each of these, so every one of these codes means the loader is
// about to say the same thing in its own words, either as its refusal of a policy
// with no rules to run or as the decoder's complaint about the value's type.
// Neither wording contains the walk's, so this is what lets the backstop
// recognize the restatement and leave one mistake as one issue.
//
// The types are read from the decoder's own targets rather than written out, so
// renaming one cannot leave a restatement unrecognized. Pairing a code with its
// type is what keeps the fold on the value the walk located instead of on
// everything the decoder says about that line (see coversComplaint).
//
// TestValidateBundleReportsEachDefectOnce drives one bundle per shape check, so a
// check added without its code here fails rather than reporting twice.
var valueShapeTypes = map[string]string{
	"policies-not-list":  reflect.TypeFor[[]structuredPolicy]().String(),
	"policy-not-mapping": reflect.TypeFor[structuredPolicy]().String(),
	"missing-rules":      reflect.TypeFor[[]structuredRule]().String(),
	"rules-not-list":     reflect.TypeFor[[]structuredRule]().String(),
	"empty-rules":        reflect.TypeFor[[]structuredRule]().String(),
}

// unlocatedDecodeMessage returns the loader's failure with the decoder
// complaints a located issue already reports removed, and false when that leaves
// nothing to report. The decoder gathers every field it refuses into one error,
// so a restatement has to be dropped one complaint at a time: dropping the whole
// error would take the fields only the decoder finds down with it, and hide them
// until the located defect is fixed and lint rerun. An error that is not the
// decoder's is passed through for the comparison the caller makes on the whole
// message.
func unlocatedDecodeMessage(err error, located []Issue) (string, bool) {
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		return err.Error(), true
	}
	kept := make([]string, 0, len(typeErr.Errors))
	for _, complaint := range typeErr.Errors {
		if slices.ContainsFunc(located, func(issue Issue) bool { return coversComplaint(issue, complaint) }) {
			continue
		}
		kept = append(kept, complaint)
	}
	if len(kept) == 0 {
		return "", false
	}
	if len(kept) == len(typeErr.Errors) {
		return err.Error(), true
	}
	// The decode error is wrapped in the source and policy it came from, so the
	// remaining complaints replace the original ones in place rather than losing
	// that prefix.
	return strings.Replace(err.Error(), typeErr.Error(), (&yaml.TypeError{Errors: kept}).Error(), 1), true
}

// coversComplaint reports whether a located issue already reports what one of
// the decoder's complaints says. A complaint quoted verbatim is one this run has
// already reported, which is how the per-policy expansion keeps the bundle-wide
// decode from restating what it found. Otherwise only a rule shape is folded: a
// rules value the walk calls "not a list" is a value the decoder cannot
// unmarshal into its rule slice, one mistake in two vocabularies, and the line
// the decoder names is the line the walk located it on. The same holds one level
// up, for the policies list and for an entry of it that is not a policy.
//
// The line is not enough to tell a restatement from a second defect: a line
// carries as many fields as the author writes on it, and the line a missing rules
// list is reported on is the policy's first field whatever that field is. So the
// complaint has to be about the value the located issue describes, which it says
// by naming the type the decoder could not read that value into. Folding on the
// line alone dropped a field only the decoder finds and handed it back a lint run
// later, once the located defect beside it was fixed.
func coversComplaint(issue Issue, complaint string) bool {
	if issue.Severity == IssueHint {
		return false
	}
	if strings.Contains(issue.Message, complaint) {
		return true
	}
	shape, ok := valueShapeTypes[issue.Code]
	if !ok {
		return false
	}
	line := lineFromYAMLError(complaint)
	return line > 0 && line == issue.Line && strings.Contains(complaint, "into "+shape)
}

// lineFromYAMLError returns the 1-based line a YAML decode error names, or zero
// when it names none. The decoder reports type mismatches as "line N: cannot
// unmarshal ...", which is the only position information available for a field
// the node walk does not model.
func lineFromYAMLError(message string) int {
	_, after, ok := strings.Cut(message, "line ")
	if !ok {
		return 0
	}
	digits := after
	if idx := strings.IndexFunc(after, func(r rune) bool { return r < '0' || r > '9' }); idx >= 0 {
		digits = after[:idx]
	}
	line, err := strconv.Atoi(digits)
	if err != nil || line < 1 {
		return 0
	}
	return line
}

// issueAt builds an issue anchored at a YAML node.
func issueAt(node *yaml.Node, severity IssueSeverity, code, message string) Issue {
	issue := Issue{RuleIndex: NoRule, Severity: severity, Code: code, Message: message}
	if node != nil {
		issue.Line = node.Line
		issue.Column = node.Column
	}
	return issue
}

// ruleIssue tags an issue with the rule it came from.
func ruleIssue(idx int, issue Issue) Issue {
	issue.RuleIndex = idx
	return issue
}

// DeclaredVarNames returns the variable names declared under a policy node's
// vars mapping, in author order. Callers use it to declare those names before
// compiling the policy's conditions.
func DeclaredVarNames(policyNode *yaml.Node) []string {
	var names []string
	varsNode := MappingValue(policyNode, "vars")
	if varsNode == nil || varsNode.Kind != yaml.MappingNode {
		return names
	}
	for i := 0; i+1 < len(varsNode.Content); i += 2 {
		k := varsNode.Content[i]
		// varKeyName normalizes, because the expansion binds the normalized
		// spelling and a condition is compiled against the names it can use, and
		// reads a null key as binding nothing, as the decoder does. Declaring the
		// text of a null key would put a name in scope that the expanded policy
		// never binds.
		if name := varKeyName(k); name != "" && !isMergeKey(k) {
			names = append(names, name)
		}
	}
	return names
}

// MappingValue returns the value node for a key inside a YAML mapping node, or
// nil when the node is not a mapping, the key is absent, or the key is present
// with an explicitly null value. It reads only what the document says: anchors,
// aliases, merge keys, and rewriting tags are rejected (see
// refusedConstructIssues) and the nodes carrying a reference are skipped, so no
// reader has to resolve them.
func MappingValue(mapNode *yaml.Node, key string) *yaml.Node {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		k := mapNode.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			if isNullNode(mapNode.Content[i+1]) {
				return nil
			}
			return mapNode.Content[i+1]
		}
	}
	return nil
}

// isNullNode reports whether a value node is YAML's null: `key: null`, `key: ~`,
// and a key written with no value at all all resolve to the !!null tag. The
// decoder leaves the corresponding Go field at its zero value, which for every
// optional field of a policy is indistinguishable from the field being absent,
// so the node walk has to read a null the same way. Without this it reports
// `mode: null` as an invalid mode and `entrypoints: null` as a malformed list
// for a bundle the loader accepts, and treats the literal text "null" as a
// policy name two such policies would then collide on.
func isNullNode(node *yaml.Node) bool {
	return node != nil && node.Kind == yaml.ScalarNode && node.Tag == "!!null"
}

// hasMergeKey reports whether a mapping node merges another mapping's entries
// into itself. Only a merge key on the mapping itself can add keys to it, which
// is what makes a bundle whose policies key arrives that way not a bundle
// missing the key.
func hasMergeKey(mapNode *yaml.Node) bool {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		if isMergeKey(mapNode.Content[i]) {
			return true
		}
	}
	return false
}

// isMergeKey reports whether a mapping key is YAML's merge key, the "<<" that
// pulls another mapping's entries into this one.
//
// The question is the tag YAML resolves, not the text the key is spelled with. A
// quoted "<<" is an ordinary string key that merges nothing, and a bundle may
// legitimately carry it wherever it accepts arbitrary keys, in its metadata and in
// a rule's details. Reading the text instead named a merge the author did not
// write and, worse, made every check that reads the document's values skip the
// policy carrying it (see resolvesElsewhere).
//
// Tightening this cannot let a merge through unreported: yaml.v3 merges a key when
// it is a scalar whose value is "<<" and whose tag resolves to !!merge, which is
// what ShortTag answers, so every spelling the decoder acts on is refused here,
// including a tag written verbatim as its URI. A key the author explicitly tagged
// !!merge is refused whatever its name, which is the safe direction to err in.
func isMergeKey(key *yaml.Node) bool {
	return key != nil && key.Kind == yaml.ScalarNode && key.ShortTag() == mergeTag
}

// Messages for the YAML constructs a policy bundle does not accept. Each names
// the alternative, since the author is reaching for the construct to say
// something and deserves to be told how to say it plainly.
const (
	anchorNotSupported = "policy bundles do not support YAML anchors and aliases; " +
		"share rules with a separate --policy file or reuse expressions with vars:"
	mergeKeyNotSupported = "policy bundles do not support YAML merge keys; " +
		"share rules with a separate --policy file or reuse expressions with vars:"
	opaqueScalarNotSupported = "policy bundles do not support YAML tags that rewrite a scalar; " +
		"write the value the policy means"
)

// nullTag is YAML's resolved tag for every spelling of null.
const nullTag = "!!null"

// mergeTag is YAML's resolved tag for the merge key, in every spelling of it.
const mergeTag = "!!merge"

// strTag is YAML's resolved tag for a string scalar. It is what tells a var whose
// value is the author's own CEL from one Deputy has to marshal into CEL for them,
// so the decoder and the walk share the spelling rather than each writing it out.
const strTag = "!!str"

// rewritesItsText reports whether a scalar's value is not the text the document
// writes for it. A YAML tag can arrange exactly that: `action: !!binary ZGVueQ==`
// is written as base64 and read as "deny", so the walk judging the written text
// and the decoder reading the value disagree about the same field.
//
// The test is the divergence itself rather than a list of tags, so a tag nobody
// thought of cannot reopen the gap. Null is excluded because it is the one
// rewrite every reader of a bundle already models the same way: the decoder
// leaves the field at its zero value and the walk reads the key as unset (see
// isNullNode).
func rewritesItsText(node *yaml.Node) bool {
	if node == nil || node.Kind != yaml.ScalarNode || node.Tag == nullTag {
		return false
	}
	var text string
	// A scalar the decoder cannot read as a string rewrites nothing: it fails the
	// same way for the loader, which is a disagreement neither reader can hide.
	if err := node.Decode(&text); err != nil {
		return false
	}
	return text != node.Value
}

// refusedConstructIssues reports every YAML construct a policy bundle does not
// accept: anchors, aliases, merge keys, and tags that rewrite a scalar. It is
// the one definition of that vocabulary, which is what keeps the linter and the
// loader refusing the same documents; both reach it, validation directly and
// loading through bundleRefusalError.
//
// Supporting them is closed for now rather than closed forever: nothing stops
// Deputy from resolving them, and this can be revisited if a real need appears.
// Two reasons to say no today. A policy bundle is a security control whose job
// is to state plainly what it blocks, and an aliased policy means the text a
// reviewer reads is not the policy that runs, while merge-key precedence adds a
// rule the reviewer has to know before they can tell what a policy does. A
// rewriting tag is the same defect spelled shorter: `action: !!binary ZGVueQ==`
// reviews as base64 and denies. And every YAML feature the format allows has to
// be implemented identically by every reader of a bundle, of which there are
// already several walking nodes directly; that divergence is what let an aliased
// bundle load fine and lint as broken, and what made a tagged action lint as
// invalid and compile as deny. The sharing these constructs offer is already
// served by repeatable --policy files across bundles and by vars: within one.
func refusedConstructIssues(node *yaml.Node) []Issue {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.AliasNode {
		// Do not follow the alias: its target is reported where it is defined.
		return []Issue{issueAt(node, IssueError, "yaml-anchor", anchorNotSupported)}
	}
	var issues []Issue
	if node.Anchor != "" {
		issues = append(issues, issueAt(node, IssueError, "yaml-anchor", anchorNotSupported))
	}
	if rewritesItsText(node) {
		issues = append(issues, issueAt(node, IssueError, "yaml-opaque-scalar", opaqueScalarNotSupported))
	}
	for i := 0; i < len(node.Content); i++ {
		child := node.Content[i]
		// A mapping's content alternates key, value. A merge key names the
		// construct, so report it and skip the alias it merges from, which would
		// otherwise say the same thing twice.
		if node.Kind == yaml.MappingNode && i%2 == 0 && isMergeKey(child) {
			issues = append(issues, issueAt(child, IssueError, "yaml-merge-key", mergeKeyNotSupported))
			i++
			continue
		}
		issues = append(issues, refusedConstructIssues(child)...)
	}
	return issues
}

// resolvesElsewhere reports whether a node says part of what it means somewhere
// other than where it is written: a YAML alias, whose value lives at the anchor
// it names, or a merge key, which pulls another mapping's entries in. Deputy
// refuses both (see refusedConstructIssues), so no reader resolves them, and a walk that
// cannot follow them can only describe the reference rather than the value.
// Nodes carrying one are therefore skipped by the checks that read a document's
// values.
//
// An anchor definition is not a reference: `description: &text foo` says foo
// right where a reader looks for it. It is still refused, but every other check
// around it reads what the author wrote and reports in the same pass, so the
// refusal costs no extra lint run.
func resolvesElsewhere(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Kind == yaml.AliasNode {
		return true
	}
	for i, child := range node.Content {
		if node.Kind == yaml.MappingNode && i%2 == 0 && isMergeKey(child) {
			return true
		}
		if resolvesElsewhere(child) {
			return true
		}
	}
	return false
}

// bundleRefusalError reports the first construct in data that a policy bundle
// does not accept as an error naming the file and line, for callers that load a
// bundle rather than validate it. It returns nil for a document that is not a
// policy bundle, and for one that uses none of those constructs, which is every
// bundle Deputy ships. It gates on the same shape probe the linter uses rather
// than on a well-formed policies list, so a bundle whose list is itself an
// alias, or whose policies key arrives through a root merge key, is refused
// instead of quietly resolved by the decoder.
//
// It shares refusedConstructIssues with validation rather than restating the
// vocabulary, so the loader cannot come to accept a document the linter rejects.
func bundleRefusalError(data []byte, path string) error {
	if !LooksLikeStructuredBundle(data) {
		return nil
	}
	root := &yaml.Node{}
	if err := yaml.Unmarshal(data, root); err != nil || len(root.Content) == 0 {
		return nil
	}
	issues := refusedConstructIssues(root)
	if len(issues) == 0 {
		return nil
	}
	return fmt.Errorf("%s:%d: %s", path, issues[0].Line, issues[0].Message)
}
