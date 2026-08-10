package policy

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
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

// ValidateBundle reports every structural problem in a structured policy bundle:
// unknown entrypoints, commands and actions, duplicate policy names, malformed
// rules, and conditions that do not compile. It is the one implementation behind
// both `deputy policy lint` and the editor's diagnostics, so a policy that lints
// clean is a policy the editor considers clean.
//
// It returns an error only when the text is not YAML at all; every other problem
// comes back as an Issue so callers can report them all at once. Loading the
// bundle is the last resort check, reported only when nothing more precise was
// found, because a load failure repeats what the located issues already say.
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
	for _, item := range policiesNode.Content {
		if item.Kind != yaml.MappingNode {
			issues = append(issues, issueAt(item, IssueError, "policy-not-mapping", "policy must be a mapping"))
			continue
		}
		issues = append(issues, validatePolicyNode(item, seenNames, opts)...)
	}
	// Load the whole bundle so problems the node walk does not model (mode, vars,
	// empty rule lists) are still reported, but only when nothing located said it
	// first: the loader stops at the first failure and cannot point at a line.
	if slices.ContainsFunc(issues, func(i Issue) bool { return i.Severity != IssueHint }) {
		return issues, nil
	}
	source := cmp.Or(opts.Source, "policy")
	if _, err := ParseStructuredSources([]byte(text), source); err != nil {
		issues = append(issues, Issue{RuleIndex: NoRule, Severity: IssueWarning, Code: "bundle-error", Message: err.Error()})
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

	declaredVars := DeclaredVarNames(item)
	issues = append(issues, validateRules(item, name, append(declaredVars, opts.ExtraVars...), opts.CheckWhen)...)
	for i := range issues {
		if issues[i].Policy == "" {
			issues[i].Policy = name
		}
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
	var issues []Issue
	for idx, rule := range rulesNode.Content {
		if rule.Kind != yaml.MappingNode {
			issues = append(issues, ruleIssue(idx, issueAt(rule, IssueError, "rule-not-mapping", "rule must be a mapping")))
			continue
		}
		whenNode := MappingValue(rule, "when")
		if whenNode == nil || whenNode.Kind != yaml.ScalarNode {
			issues = append(issues, ruleIssue(idx, issueAt(rule, IssueError, "missing-when", "rule missing 'when' expression")))
			continue
		}
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
		if k.Kind == yaml.ScalarNode && strings.TrimSpace(k.Value) != "" {
			names = append(names, k.Value)
		}
	}
	return names
}

// MappingValue returns the value node for a key inside a YAML mapping node, or
// nil when the node is not a mapping or the key is absent.
func MappingValue(mapNode *yaml.Node, key string) *yaml.Node {
	if mapNode == nil || mapNode.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(mapNode.Content); i += 2 {
		k := mapNode.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return mapNode.Content[i+1]
		}
	}
	return nil
}
