package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

// structuredBundle represents the top-level structure of a YAML policy bundle.
// It contains global metadata and a list of policy definitions.
type structuredBundle struct {
	Metadata map[string]any     `yaml:"metadata,omitempty"` // Metadata contains global bundle metadata.
	Policies []structuredPolicy `yaml:"policies"`           // Policies is the list of policies in the bundle.
}

// structuredPolicy defines a single policy within a bundle, including its
// metadata, execution mode, variables, and evaluation rules.
type structuredPolicy struct {
	Name        string           `yaml:"name"`                  // Name is the policy name.
	Description string           `yaml:"description,omitempty"` // Description describes the policy's purpose.
	Ecosystems  []string         `yaml:"ecosystems,omitempty"`  // Ecosystems limits the policy to specific ecosystems.
	Entrypoints []string         `yaml:"entrypoints,omitempty"` // Entrypoints limits the policy to specific entrypoints.
	Commands    []string         `yaml:"commands,omitempty"`    // Commands limits the policy to specific CLI commands.
	Mode        string           `yaml:"mode,omitempty"`        // Mode is the execution mode (e.g., "enforce", "advisory").
	Vars        orderedVars      `yaml:"vars,omitempty"`        // Vars defines variables used in the policy rules.
	Rules       []structuredRule `yaml:"rules"`                 // Rules is the list of evaluation rules.
}

// orderedVars preserves author order from YAML mappings so dependent vars
// expand deterministically (later vars can reference earlier ones).
type orderedVars []varKV

// varKV represents a single variable definition (key-value pair) in an ordered list.
type varKV struct {
	Name     string // Name is the variable name.
	Value    any    // Value is the variable value.
	IsString bool   // IsString indicates if the value was parsed as a string.
}

// exprString converts the variable's value into a CEL-compatible string representation.
// Strings are returned as-is (quoted by the caller if needed), while other types
// are JSON-marshaled.
func (kv varKV) exprString() string {
	if kv.IsString {
		if s, ok := kv.Value.(string); ok {
			return s
		}
	}
	b, err := json.Marshal(kv.Value)
	if err != nil {
		return "null"
	}
	return string(b)
}

// normalizeVarName trims surrounding whitespace from a variable name, so that
// "blocked" and " blocked " are the one name they read as. A var name becomes a
// CEL identifier, and CEL reads the padded spelling as the bare one, so the two
// bind the same variable and the second shadows the first. Validation reports
// that as a duplicate, so every reader has to fold them together or a bundle the
// linter rejects would still compile.
func normalizeVarName(name string) string {
	return strings.TrimSpace(name)
}

// UnmarshalYAML implements the yaml.Unmarshaler interface to decode a mapping
// into an ordered list of key-value pairs. Variable names are normalized as they
// are read, so every reader of a bundle sees the name CEL will bind.
func (o *orderedVars) UnmarshalYAML(node *yaml.Node) error {
	if node == nil {
		return nil
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("vars must be a mapping")
	}
	if len(node.Content)%2 != 0 {
		return fmt.Errorf("vars mapping must have even number of nodes")
	}
	var out []varKV
	for i := 0; i < len(node.Content); i += 2 {
		k := node.Content[i]
		v := node.Content[i+1]
		var kv varKV
		if err := k.Decode(&kv.Name); err != nil {
			return err
		}
		kv.Name = normalizeVarName(kv.Name)
		// Detect string vs other scalars/collections
		if v.Kind == yaml.ScalarNode && v.Tag == "!!str" {
			if err := v.Decode(&kv.Value); err != nil {
				return err
			}
			kv.IsString = true
		} else {
			if err := v.Decode(&kv.Value); err != nil {
				return err
			}
			kv.IsString = false
		}
		out = append(out, kv)
	}
	*o = out
	return nil
}

// UnmarshalJSON implements the json.Unmarshaler interface. Since JSON maps are
// unordered, this implementation sorts keys alphabetically to ensure deterministic
// behavior, though it loses the original author order.
func (o *orderedVars) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	keys := slices.Sorted(maps.Keys(m))
	out := make([]varKV, 0, len(keys))
	for _, k := range keys {
		val := m[k]
		_, isString := val.(string)
		out = append(out, varKV{Name: normalizeVarName(k), Value: val, IsString: isString})
	}
	*o = out
	return nil
}

// Names returns the ordered variable names.
func (o orderedVars) Names() []string {
	if len(o) == 0 {
		return nil
	}
	out := make([]string, 0, len(o))
	for _, kv := range o {
		out = append(out, kv.Name)
	}
	return out
}

// structuredRule defines a single evaluation rule within a policy. It maps a
// condition (When) to an outcome (Action) and optional metadata.
type structuredRule struct {
	Action      string            `yaml:"action"`                // Action is the outcome if the rule matches (e.g., "deny").
	When        string            `yaml:"when"`                  // When is the CEL condition that triggers the rule.
	Reason      string            `yaml:"reason,omitempty"`      // Reason explains why the rule matched.
	Status      *int              `yaml:"status,omitempty"`      // Status is the HTTP status code to return.
	Headers     map[string]string `yaml:"headers,omitempty"`     // Headers are HTTP headers to set.
	Remediation string            `yaml:"remediation,omitempty"` // Remediation suggests how to fix the violation.
	Details     map[string]any    `yaml:"details,omitempty"`     // Details provides extra context.
}

// normalizeNames trims surrounding whitespace from every policy name, so that
// "audit" and " audit " are the one name they read as. A name identifies a
// policy: validation reports the second as a duplicate, and the name is what
// ends up in a source name and in the generated policy.name metadata, so the
// loader has to fold them together too or a bundle the linter rejects would
// still compile.
func (b *structuredBundle) normalizeNames() {
	for i := range b.Policies {
		b.Policies[i].Name = strings.TrimSpace(b.Policies[i].Name)
	}
}

// policyNeedsRuleMessage is how a reader of a bundle says that a policy has no
// rules to run. The node walk locates the same defect from the document, in its
// own words, so validation matches this spelling to fold the loader's
// restatement of it; one constant is what keeps the two readers from drifting
// into reporting one mistake twice.
const policyNeedsRuleMessage = "policy must contain at least one rule"

// tryParseStructuredBundle attempts to parse a byte slice as a structured YAML bundle.
// It returns the generated CEL sources if successful, or a boolean indicating
// whether the input looked like a bundle but failed validation. A file that has
// the shape of an authored bundle but does not decode reports the decode error
// rather than being dismissed as an unknown format, since the author wrote a
// policy and deserves to be told which field is wrong.
func tryParseStructuredBundle(data []byte, path string) ([]Source, bool, error) {
	if IsCompiledBundle(data) {
		return nil, false, nil
	}
	// The decoder would resolve anchors, and read a tagged scalar as something
	// other than its text, without saying so; refuse both here, since loading and
	// validating a bundle must agree on what the format accepts.
	if err := bundleRefusalError(data, path); err != nil {
		return nil, false, err
	}
	return decodeStructuredBundle(data, path)
}

// decodeStructuredBundle turns an authored bundle into policy sources, without
// the refusal of YAML anchors that loading one puts in front of the decoder.
//
// Only validation reads a bundle this way, for its last backstop: it has already
// located every anchor in the document itself, and the refusal stops at the
// first one, so going through it would hide the bundle-level shapes that nothing
// but decoding finds and cost the author a lint run. It is safe there because
// validation skips this whenever the document holds an alias or a merge key, the
// constructs that would make the decoder read something other than what the
// document says. Every other caller loads a bundle to run it and must refuse
// them, so it calls tryParseStructuredBundle.
func decodeStructuredBundle(data []byte, path string) ([]Source, bool, error) {
	var bundle structuredBundle
	if err := yaml.Unmarshal(data, &bundle); err != nil {
		if LooksLikeStructuredBundle(data) {
			return nil, false, fmt.Errorf("%s: %w", path, err)
		}
		return nil, false, nil
	}
	if len(bundle.Policies) == 0 {
		return nil, false, nil
	}
	bundle.normalizeNames()
	seenNames := map[string]struct{}{}
	var sources []Source
	for _, pol := range bundle.Policies {
		if len(pol.Rules) == 0 {
			return nil, false, fmt.Errorf("%s/%s: %s", path, pol.Name, policyNeedsRuleMessage)
		}
		if pol.Name != "" {
			if _, dup := seenNames[pol.Name]; dup {
				return nil, false, fmt.Errorf("%s/%s: duplicate policy name", path, pol.Name)
			}
			seenNames[pol.Name] = struct{}{}
		}
		src, err := pol.toCELSource()
		if err != nil {
			return nil, false, fmt.Errorf("%s/%s: %w", path, pol.Name, err)
		}
		name := pol.Name
		if name == "" {
			name = path
		}
		sources = append(sources, Source{
			Name: fmt.Sprintf("%s::%s", path, name),
			Body: src,
		})
	}
	return sources, true, nil
}

// TryParseStructuredBundleBytes parses data into a structuredBundle and returns
// it plus a parsed flag. A bundle already compiled by `deputy policy bundle` is
// reported as not parsed, because its policies hold compiled CEL rather than
// authored rules and callers must handle it as a compiled bundle instead.
func TryParseStructuredBundleBytes(data []byte) (*structuredBundle, bool, error) {
	if IsCompiledBundle(data) {
		return nil, false, nil
	}
	var bundle structuredBundle
	if err := yaml.Unmarshal(data, &bundle); err != nil {
		return nil, false, nil
	}
	if len(bundle.Policies) == 0 {
		return nil, false, nil
	}
	bundle.normalizeNames()
	return &bundle, true, nil
}

// ParseStructuredSources parses a structured YAML bundle (same format accepted by
// `deputy policy` commands) into a slice of policy sources. The virtualPath is
// used only for error context and source naming; callers can provide an in-memory
// pseudo path such as "buffer" or a real file path.
func ParseStructuredSources(data []byte, virtualPath string) ([]Source, error) {
	sources, ok, err := tryParseStructuredBundle(data, virtualPath)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%s: not a valid structured policy (expected 'policies:' key with at least one policy)", virtualPath)
	}
	return sources, nil
}

// toCELSource compiles the structured policy into a raw CEL source string.
// It generates the necessary metadata comments and constructs the rule evaluation logic.
func (p structuredPolicy) toCELSource() (string, error) {
	if len(p.Rules) == 0 {
		return "", errors.New(policyNeedsRuleMessage)
	}
	for _, ep := range p.Entrypoints {
		if !IsAllowedEntrypoint(ep) {
			return "", fmt.Errorf("invalid entrypoint %q", ep)
		}
	}
	normalizedCommands := make([]string, 0, len(p.Commands))
	seenCommands := map[string]struct{}{}
	for _, cmd := range p.Commands {
		if !IsAllowedCommand(cmd) {
			return "", fmt.Errorf("invalid command %q", cmd)
		}
		normalized := NormalizeCommand(cmd)
		if _, ok := seenCommands[normalized]; ok {
			continue
		}
		seenCommands[normalized] = struct{}{}
		normalizedCommands = append(normalizedCommands, normalized)
	}
	p.Commands = normalizedCommands
	if p.Mode != "" {
		mode, err := ValidateMode(p.Mode)
		if err != nil {
			return "", err
		}
		p.Mode = mode
	}
	var builder strings.Builder
	builder.WriteString("[]")
	for i, rule := range p.Rules {
		expr, err := rule.toRuleExpr(p.Ecosystems)
		if err != nil {
			return "", fmt.Errorf("rule[%d]: %w", i, err)
		}
		builder.WriteString(" + ")
		builder.WriteString(expr)
	}
	body, err := p.wrapVars(builder.String())
	if err != nil {
		return "", err
	}
	metadata := []string{}
	if p.Name != "" {
		metadata = append(metadata, fmt.Sprintf("//! policy.name = \"%s\"", escapeComment(p.Name)))
	}
	if p.Description != "" {
		metadata = append(metadata, fmt.Sprintf("//! policy.description = \"%s\"", escapeComment(p.Description)))
	}
	if len(p.Entrypoints) > 0 {
		metadata = append(metadata, fmt.Sprintf("//! policy.entrypoints = \"%s\"", strings.Join(p.Entrypoints, ",")))
	}
	if len(p.Commands) > 0 {
		metadata = append(metadata, fmt.Sprintf("//! policy.commands = \"%s\"", strings.Join(p.Commands, ",")))
	}
	if p.Mode != "" && p.Mode != "enforce" {
		metadata = append(metadata, fmt.Sprintf("//! policy.mode = \"%s\"", p.Mode))
	}
	if len(p.Ecosystems) > 0 {
		metadata = append(metadata, fmt.Sprintf("//! policy.ecosystems = \"%s\"", strings.Join(p.Ecosystems, ",")))
	}
	if len(metadata) == 0 {
		return body, nil
	}
	return strings.Join(metadata, "\n") + "\n" + body, nil
}

// wrapVars binds a policy's variables around a CEL body, one comprehension per
// variable in reverse author order so an earlier var is in scope for a later
// one. Names have to be unique and non-empty, since a duplicate would silently
// shadow the binding before it.
//
// It is separate from the rest of the expansion because a policy's vars are
// wrong or right on their own: validation wraps an empty body with it to report
// vars that do not compile in a policy whose rules the walk has already found a
// defect in, which the whole-policy expansion cannot do.
func (p structuredPolicy) wrapVars(body string) (string, error) {
	if len(p.Vars) == 0 {
		return body, nil
	}
	seen := map[string]struct{}{}
	for _, kv := range p.Vars {
		if strings.TrimSpace(kv.Name) == "" {
			return "", fmt.Errorf("vars must have non-empty names")
		}
		if _, ok := seen[kv.Name]; ok {
			return "", fmt.Errorf("duplicate var name %q", kv.Name)
		}
		seen[kv.Name] = struct{}{}
	}
	for _, v := range slices.Backward(p.Vars) {
		body = fmt.Sprintf("([%s]).map(%s, %s)[0]", v.exprString(), v.Name, body)
	}
	return body, nil
}

// toRuleExpr converts a structured rule into a CEL expression string.
// It handles ecosystem filtering and constructs the conditional logic.
func (r structuredRule) toRuleExpr(ecosystems []string) (string, error) {
	when := strings.TrimSpace(r.When)
	if when == "" {
		return "", fmt.Errorf("rule missing 'when'")
	}
	if len(ecosystems) > 0 {
		quoted := make([]string, len(ecosystems))
		for i, eco := range ecosystems {
			quoted[i] = fmt.Sprintf("\"%s\"", eco)
		}
		guard := fmt.Sprintf("(request.?ecosystem.orValue(\"\") in [%s]) || (pkg.ecosystem in [%s])", strings.Join(quoted, ","), strings.Join(quoted, ","))
		when = fmt.Sprintf("((%s) && (%s))", guard, when)
	}
	if strings.TrimSpace(r.Action) == "" {
		return "", fmt.Errorf("rule missing action")
	}
	normalizedAction, err := ValidateActionType(r.Action)
	if err != nil {
		return "", err
	}
	action := map[string]any{"action": normalizedAction}
	if r.Reason != "" {
		action["reason"] = r.Reason
	}
	if r.Remediation != "" {
		action["remediation"] = r.Remediation
	}
	if r.Status != nil {
		action["status"] = *r.Status
	}
	if len(r.Headers) > 0 {
		action["headers"] = r.Headers
	}
	if len(r.Details) > 0 {
		action["details"] = r.Details
	}
	actionJSON, err := json.Marshal(action)
	if err != nil {
		return "", fmt.Errorf("marshal action: %w", err)
	}
	return fmt.Sprintf("((%s) ? [%s] : [])", when, string(actionJSON)), nil
}

// escapeComment escapes characters in a string to make it safe for inclusion
// in a generated CEL comment. Multi-line strings (from YAML | or >) must have
// newlines escaped to avoid breaking the single-line comment format.
func escapeComment(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}
