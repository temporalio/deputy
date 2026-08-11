package policy

import (
	"cmp"
	"errors"
	"fmt"
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
// A document whose "policies" key is not written directly still counts when the
// decoder finds one anyway, which a top-level merge key does. Without that
// fallback a bundle could inherit its whole policy list from an anchor and slip
// past the checks that key off this probe, the anchor refusal among them.
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
	return decodesWithPolicies(data)
}

// bundlePoliciesKey is the mapping key that marks a document as an authored
// policy bundle. bundleKeyMatchesStructTag pins it to the field the decoder
// reads, so the probe and the loader cannot drift apart.
const bundlePoliciesKey = "policies"

// unparsedBundleKey matches the bundle's policies key written at the top level
// of a document, in raw text. It is deliberately a last resort: YAML that parses
// is always probed by walking its nodes, and this runs only for a document the
// parser rejected outright, where no structure is available to walk.
var unparsedBundleKey = regexp.MustCompile(`(?m)^` + yamlKeyPattern(bundlePoliciesKey) + `[ \t]*:`)

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
func writesBundleKey(data []byte) bool {
	return unparsedBundleKey.Match(data)
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

// decodesWithPolicies reports whether data decodes into a bundle carrying at
// least one policy. It is how the shape probe sees a policies key the node walk
// cannot: the decoder resolves the aliases and merge keys the walk refuses to
// follow, so this answers "would a reader that resolves them find policies here"
// without any reader having to act on the resolved value.
func decodesWithPolicies(data []byte) bool {
	var bundle structuredBundle
	if err := yaml.Unmarshal(data, &bundle); err != nil {
		return false
	}
	return len(bundle.Policies) > 0
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
	// Anchors are reported before anything else reads the document, so the rest
	// of validation, and every other reader of a bundle, sees only plain nodes.
	// The scan comes before the policies lookup because a root merge key can
	// supply the whole list, which would otherwise read as a missing key. It does
	// not stop the checks that follow: a refused anchor must not hide an unrelated
	// typo, or an uncompilable var, and cost the author a second lint run.
	anchors := anchorIssues(root)
	issues = append(issues, anchors...)
	policiesNode := MappingValue(doc, bundlePoliciesKey)
	if policiesNode == nil {
		// A root merge key supplies the whole list, so a document carrying one is
		// not missing it and the merge key is the only mistake to report. Nothing
		// else the document does can put the key here, so an anchor elsewhere does
		// not withhold this.
		if !hasMergeKey(doc) {
			issues = append(issues, issueAt(doc, IssueError, "missing-policies", "missing required 'policies' list"))
		}
		return issues, nil
	}
	if policiesNode.Kind != yaml.SequenceNode {
		// An aliased list is a list once resolved, so saying it is not one would
		// describe the alias rather than the mistake. A value written directly is
		// the mistake, whatever the document does elsewhere.
		if policiesNode.Kind != yaml.AliasNode {
			issues = append(issues, issueAt(policiesNode, IssueError, "policies-not-list", "'policies' must be a list"))
		}
		return issues, nil
	}
	// An empty list is reported here rather than left to the loader backstop, so
	// the diagnostic names the line the author has to fill in.
	if len(policiesNode.Content) == 0 {
		return append(issues, issueAt(policiesNode, IssueError, "empty-policies", "'policies' must contain at least one policy")), nil
	}
	seenNames := map[string]struct{}{}
	source := cmp.Or(opts.Source, "policy")
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
		// A policy the walk already located an error in is not expanded: its
		// expansion is expected to fail too, and restating that failure in
		// generated CEL the author never wrote would only obscure the real defect.
		if slices.ContainsFunc(located, func(is Issue) bool { return is.Severity == IssueError }) {
			continue
		}
		issues = append(issues, expandedPolicyIssues(item, source, opts.ExtraVars, located)...)
	}
	// Loading the whole bundle is the last backstop, for the shapes that belong to
	// no single policy, such as bundle metadata of the wrong type. It stops at its
	// first failure, which is why it runs after every policy has been expanded on
	// its own and adds only what is not already reported. A document carrying an
	// anchor skips it outright: the loader stops at the first one, which the scan
	// above already located.
	if len(anchors) == 0 {
		if _, err := ParseStructuredSources([]byte(text), source); err != nil {
			issues = append(issues, backstopIssue(err, source, doc, issues)...)
		}
	}
	return issues, nil
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
// located is what the walk already reported for this policy, so a failure that
// restates one of those is dropped and a single mistake stays a single issue.
func expandedPolicyIssues(item *yaml.Node, source string, extraVars []string, located []Issue) []Issue {
	var pol structuredPolicy
	// Decoding resolves aliases and merge keys, which the format refuses; that is
	// safe here because a policy carrying one anywhere beneath it never reaches
	// this point, so the decoder reads only what the policy itself writes.
	if err := item.Decode(&pol); err != nil {
		return backstopIssue(fmt.Errorf("%s: %w", source, err), source, item, located)
	}
	pol.Name = strings.TrimSpace(pol.Name)
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

// validateVars checks the vars mapping: it must be a mapping, and every variable
// needs a unique non-empty name, since duplicates silently shadow each other
// when the policy is expanded.
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
		name := strings.TrimSpace(key.Value)
		if key.Kind != yaml.ScalarNode || name == "" {
			issues = append(issues, issueAt(key, IssueError, "empty-var-name", "vars must have non-empty names"))
			continue
		}
		if _, dup := seen[name]; dup {
			issues = append(issues, issueAt(key, IssueError, "duplicate-var", fmt.Sprintf("duplicate var name %q", name)))
		}
		seen[name] = struct{}{}
	}
	return issues
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
		return []Issue{issueAt(rulesNode, IssueError, "empty-rules", "policy must contain at least one rule")}
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
	}
	return issues
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
func loaderMessage(err error, source string, located []Issue) (string, bool) {
	message := err.Error()
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
	}
	return message, false
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
		if k.Kind == yaml.ScalarNode && !isMergeKey(k) && strings.TrimSpace(k.Value) != "" {
			names = append(names, k.Value)
		}
	}
	return names
}

// MappingValue returns the value node for a key inside a YAML mapping node, or
// nil when the node is not a mapping, the key is absent, or the key is present
// with an explicitly null value. It reads only what the document says: anchors,
// aliases, and merge keys are rejected (see anchorIssues) and the nodes carrying
// them are skipped, so no reader has to resolve them.
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
func isMergeKey(key *yaml.Node) bool {
	return key.Tag == "!!merge" || key.Value == "<<"
}

// Messages for the YAML constructs a policy bundle does not accept. Both name
// the alternative, since the author is trying to avoid repeating themselves and
// deserves to be told how.
const (
	anchorNotSupported = "policy bundles do not support YAML anchors and aliases; " +
		"share rules with a separate --policy file or reuse expressions with vars:"
	mergeKeyNotSupported = "policy bundles do not support YAML merge keys; " +
		"share rules with a separate --policy file or reuse expressions with vars:"
)

// anchorIssues reports every YAML anchor, alias, and merge key in a bundle.
//
// Supporting them is closed for now rather than closed forever: nothing stops
// Deputy from resolving them, and this can be revisited if a real need appears.
// Two reasons to say no today. A policy bundle is a security control whose job
// is to state plainly what it blocks, and an aliased policy means the text a
// reviewer reads is not the policy that runs, while merge-key precedence adds a
// rule the reviewer has to know before they can tell what a policy does. And
// every YAML feature the format allows has to be implemented identically by
// every reader of a bundle, of which there are already several walking nodes
// directly; that divergence is what let an aliased bundle load fine and lint as
// broken. The sharing these constructs offer is already served by repeatable
// --policy files across bundles and by vars: within one.
func anchorIssues(node *yaml.Node) []Issue {
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
		issues = append(issues, anchorIssues(child)...)
	}
	return issues
}

// resolvesElsewhere reports whether a node says part of what it means somewhere
// other than where it is written: a YAML alias, whose value lives at the anchor
// it names, or a merge key, which pulls another mapping's entries in. Deputy
// refuses both (see anchorIssues), so no reader resolves them, and a walk that
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

// bundleAnchorError reports the first anchor, alias, or merge key in data as an
// error naming the file and line, for callers that load a bundle rather than
// validate it. It returns nil for a document that is not a policy bundle, and
// for one that uses none of those constructs, which is every bundle Deputy
// ships. It gates on the same shape probe the linter uses rather than on a
// well-formed policies list, so a bundle whose list is itself an alias, or whose
// policies key arrives through a root merge key, is refused instead of quietly
// resolved by the decoder.
func bundleAnchorError(data []byte, path string) error {
	if !LooksLikeStructuredBundle(data) {
		return nil
	}
	root := &yaml.Node{}
	if err := yaml.Unmarshal(data, root); err != nil || len(root.Content) == 0 {
		return nil
	}
	issues := anchorIssues(root)
	if len(issues) == 0 {
		return nil
	}
	return fmt.Errorf("%s:%d: %s", path, issues[0].Line, issues[0].Message)
}
