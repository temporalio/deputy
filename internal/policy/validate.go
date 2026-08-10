package policy

import (
	"cmp"
	"errors"
	"fmt"
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
// policy bundle: a mapping carrying a non-empty "policies" list. It deliberately
// does not require the bundle to decode into Deputy's types, so a policy with a
// mistyped field is still recognized as a policy and can be reported with
// located, specific errors instead of being dismissed as an unknown format.
// Compiled bundles are ruled out first: their JSON has a "policies" array too.
func LooksLikeStructuredBundle(data []byte) bool {
	if IsCompiledBundle(data) {
		return false
	}
	root := &yaml.Node{}
	if err := yaml.Unmarshal(data, root); err != nil || len(root.Content) == 0 {
		return false
	}
	policies := MappingValue(root.Content[0], "policies")
	return policies != nil && policies.Kind == yaml.SequenceNode && len(policies.Content) > 0
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
	policiesNode := MappingValue(doc, "policies")
	if policiesNode == nil {
		return append(issues, issueAt(doc, IssueError, "missing-policies", "missing required 'policies' list")), nil
	}
	if policiesNode.Kind != yaml.SequenceNode {
		return append(issues, issueAt(policiesNode, IssueError, "policies-not-list", "'policies' must be a list")), nil
	}
	seenNames := map[string]struct{}{}
	for _, entry := range policiesNode.Content {
		// A policy may be written as an alias to an anchor defined elsewhere in
		// the document. Report against the alias, which is where the author can
		// see the problem, but validate what it points at.
		item := ResolveAlias(entry)
		if item == nil || item.Kind != yaml.MappingNode {
			issues = append(issues, issueAt(entry, IssueError, "policy-not-mapping", "policy must be a mapping"))
			continue
		}
		issues = append(issues, validatePolicyNode(item, seenNames, opts)...)
	}
	// Load the whole bundle as a backstop for shapes the node walk does not model,
	// such as a rule field of the wrong type. The loader stops at its first
	// failure, so its message is dropped when a located issue already reports the
	// same thing, and is anchored on the line it names when it names one.
	source := cmp.Or(opts.Source, "policy")
	if _, err := ParseStructuredSources([]byte(text), source); err != nil {
		if message, duplicate := loaderMessage(err, source, issues); !duplicate {
			issues = append(issues, Issue{
				RuleIndex: NoRule,
				Line:      lineFromYAMLError(message),
				Column:    1,
				Severity:  IssueWarning,
				Code:      "bundle-error",
				Message:   message,
			})
		}
	}
	return issues, nil
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

// aliasDepthLimit bounds how far alias and merge-key resolution will follow
// references. YAML anchors can be nested, but a document deep enough to exceed
// this is either generated or malicious, and refusing to follow it keeps
// validation from looping on a self-referential anchor.
const aliasDepthLimit = 32

// ResolveAlias follows a YAML alias to the node its anchor defines, so callers
// can treat `- *policy` exactly as the typed decoder does. A node that is not an
// alias is returned unchanged.
func ResolveAlias(node *yaml.Node) *yaml.Node {
	for depth := 0; node != nil && node.Kind == yaml.AliasNode; depth++ {
		if depth >= aliasDepthLimit {
			return nil
		}
		node = node.Alias
	}
	return node
}

// MappingValue returns the value node for a key inside a YAML mapping node, or
// nil when the node is not a mapping or the key is absent. Aliases are followed
// on both the mapping and the value, and merge keys are searched after the
// mapping's own keys, matching how the decoder resolves inherited fields: a key
// written directly on a policy overrides one it merges in.
func MappingValue(mapNode *yaml.Node, key string) *yaml.Node {
	return mappingValue(mapNode, key, 0)
}

// mappingValue is MappingValue with the recursion depth that merge keys need,
// since a merged mapping may itself merge from another.
func mappingValue(mapNode *yaml.Node, key string, depth int) *yaml.Node {
	node := ResolveAlias(mapNode)
	if node == nil || node.Kind != yaml.MappingNode || depth >= aliasDepthLimit {
		return nil
	}
	var merges []*yaml.Node
	for i := 0; i+1 < len(node.Content); i += 2 {
		k := node.Content[i]
		if k.Kind != yaml.ScalarNode {
			continue
		}
		if k.Value == key {
			return ResolveAlias(node.Content[i+1])
		}
		if isMergeKey(k) {
			merges = append(merges, node.Content[i+1])
		}
	}
	for _, merge := range merges {
		merged := ResolveAlias(merge)
		if merged == nil {
			continue
		}
		if merged.Kind == yaml.SequenceNode {
			for _, item := range merged.Content {
				if value := mappingValue(item, key, depth+1); value != nil {
					return value
				}
			}
			continue
		}
		if value := mappingValue(merged, key, depth+1); value != nil {
			return value
		}
	}
	return nil
}

// isMergeKey reports whether a mapping key is YAML's merge key, the "<<" that
// pulls another mapping's entries into this one.
func isMergeKey(key *yaml.Node) bool {
	return key.Tag == "!!merge" || key.Value == "<<"
}
