package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
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

// exprString renders the var's value as the CEL expression the policy binds the
// name to. A string is the author's own CEL and is returned as written; every
// other value is marshaled to JSON, which is a subset of CEL's literal syntax.
//
// A value JSON has no spelling for refuses the var rather than standing in for it.
// Substituting `null` bound a name to a value the bundle does not declare: a
// `threshold: .nan` compiled, linted clean, and made `threshold == null` true, so
// the policy that ran was not the policy that was reviewed. Every value the
// decoder reads and JSON can represent is unaffected, which is every var Deputy
// ships; what is refused is the handful YAML can write and JSON cannot, the
// not-a-number and the infinities among them.
func (kv varKV) exprString() (string, error) {
	if kv.IsString {
		if s, ok := kv.Value.(string); ok {
			return s, nil
		}
	}
	b, err := json.Marshal(kv.Value)
	if err != nil {
		return "", varNotRepresentableError(kv.Name, err)
	}
	return string(b), nil
}

// varNotRepresentableFormat is how a reader of a bundle says that a var holds a
// value Deputy cannot write into the CEL a policy generates. The node walk locates
// the same defect from the document, so validation matches this spelling to fold
// the loader's restatement of it; one constant is what keeps the two readers from
// reporting one mistake twice.
const varNotRepresentableFormat = "var %q holds a value that cannot be represented: %w"

// varNotRepresentableError renders that message for one var and the marshal
// failure behind it. Both readers go through it rather than through the format, so
// neither can spell the message the other has to recognize.
func varNotRepresentableError(name string, err error) error {
	return fmt.Errorf(varNotRepresentableFormat, name, err)
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
		if v.Kind == yaml.ScalarNode && v.Tag == strTag {
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

// varBinding is what a policy can do with one of its vars: the var as authored,
// the scope its expression is evaluated in, and the reason its name binds nothing
// when it binds nothing.
type varBinding struct {
	kv    varKV       // kv is the var as the document declares it.
	scope orderedVars // scope is the vars bound above it, the names its expression may read.
	err   error       // err is why the name binds nothing, nil when it binds.
}

// bindings pairs every var with the scope its expression sees and with the reason
// its name binds nothing, in author order. A name binds nothing when it is empty,
// and a repeated name binds once: the first declaration wins, because every
// expression below it, the repeat's own included, is written against the name
// already in scope. Reporting the repeat rather than the declaration it repeats is
// also how the node walk names that defect, so the two readers point at one line.
//
// Names are compared normalized, as CEL binds them, so " blocked " and "blocked"
// are the one name they read as.
//
// Carrying the scopes is what lets validation compile the expression of a var
// whose name it has already refused: the expression is wrong or right on its own,
// in the scope it would have been evaluated in, whatever the name above it says.
// Compiling it in any other scope would invent a diagnostic, since a name the
// document declares below cannot be read from above. A reader that runs the policy
// refuses it at the first unbindable name instead (see wrapVars): a var the author
// named twice is a var Deputy cannot say which value it holds.
func (o orderedVars) bindings() []varBinding {
	out := make([]varBinding, 0, len(o))
	var bound orderedVars
	seen := make(map[string]struct{}, len(o))
	for _, kv := range o {
		binding := varBinding{kv: kv, scope: slices.Clone(bound)}
		name := normalizeVarName(kv.Name)
		_, repeated := seen[name]
		switch {
		case name == "":
			binding.err = errors.New(emptyVarNameMessage)
		case repeated:
			binding.err = fmt.Errorf(duplicateVarNameFormat, name)
		default:
			seen[name] = struct{}{}
			bound = append(bound, kv)
		}
		out = append(out, binding)
	}
	return out
}

// nestVars wraps a CEL body in one comprehension per var, in reverse author order
// so an earlier var is in scope for a later one. It checks no name: a caller that
// runs a policy validates those first (wrapVars), and validation uses this to
// compile the expression of a var whose name it has already reported.
//
// A var whose value has no CEL spelling refuses the nest, since there is no
// expression to bind the name to and standing something else in would bind a value
// the bundle does not declare (see exprString).
func nestVars(vars orderedVars, body string) (string, error) {
	for _, v := range slices.Backward(vars) {
		expr, err := v.exprString()
		if err != nil {
			return "", err
		}
		body = fmt.Sprintf("([%s]).map(%s, %s)[0]", expr, v.Name, body)
	}
	return body, nil
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

// Messages for a vars mapping a policy cannot bind. The node walk locates both
// defects from the document, in its own words, and validation folds the loader's
// restatement of them by matching the wording, so one spelling of each is what
// keeps a single mistake from being reported twice.
const (
	emptyVarNameMessage    = "vars must have non-empty names"
	duplicateVarNameFormat = "duplicate var name %q"
)

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
	return decodeStructuredBundle(data, path, LooksLikeStructuredBundle(data))
}

// decodeStructuredBundle turns an authored bundle into policy sources, without
// the refusal of YAML anchors that loading one puts in front of the decoder.
//
// isBundle is the caller's answer to whether the data is an authored bundle at
// all, which decides what a decode failure means: a policy the author wrote,
// reported so they are told which field is wrong, or a file that was never a
// bundle, left for the caller's other formats. Taking the answer rather than
// asking again is what keeps a caller that has already committed to the document
// being a bundle, as validation has, from being told it is not one.
//
// Only validation reads a bundle this way, for its last backstop: it has already
// located every anchor in the document itself, and the refusal stops at the
// first one, so going through it would hide the bundle-level shapes that nothing
// but decoding finds and cost the author a lint run. It is safe there because
// validation acts on nothing the decoder resolves: it reports the shapes the
// decode refuses, each on the line the decoder names, which for a reference is
// where the anchor it reads is written. Every other caller loads a bundle to run
// it and must refuse those constructs, so it calls tryParseStructuredBundle.
func decodeStructuredBundle(data []byte, path string, isBundle bool) ([]Source, bool, error) {
	var bundle structuredBundle
	if err := yaml.Unmarshal(data, &bundle); err != nil {
		if isBundle {
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
	var metadata metadataComments
	metadata.set("name", p.Name)
	metadata.set("description", p.Description)
	metadata.setList("entrypoints", p.Entrypoints)
	metadata.setList("commands", p.Commands)
	if p.Mode != ModeEnforce {
		metadata.set("mode", p.Mode)
	}
	metadata.setList("ecosystems", p.Ecosystems)
	if len(metadata) == 0 {
		return body, nil
	}
	return strings.Join(metadata, "\n") + "\n" + body, nil
}

// metadataComments accumulates the `//! policy.<key> = "<value>"` comments a
// generated policy carries, and is the only thing that writes one. Going through
// it is what keeps a value the author wrote from being read back as a directive.
//
// Escaping per field is what let one through: name and description escaped, and
// the four fields added beside them did not, so an ecosystems entry of
// `npm\n//! policy.mode = advisory\n//` generated a second metadata line that
// parsePolicyMetadata read as a mode, while the trailing `//` commented out the
// closing quote of the line it broke out of. The bundle read as deny, loaded as
// advisory, and linted and compiled clean. That is the same defect as an
// interpolated ecosystem guard, the text a reviewer reads not being the policy
// that runs, one layer over: escaped where the value becomes CEL and not where it
// becomes metadata.
//
// A key is Deputy's own text and a value is the author's, so only the value is
// escaped; passing an author-supplied key would be a different mistake, and no
// caller has one to pass.
type metadataComments []string

// set records one metadata comment. An empty value is dropped, since a reader
// acts on nothing it says, and the value is escaped so it can only ever be data
// on the line it is written on.
func (m *metadataComments) set(key, value string) {
	if value == "" {
		return
	}
	*m = append(*m, fmt.Sprintf("//! policy.%s = \"%s\"", key, escapeComment(value)))
}

// setList records one metadata comment holding a list, joined with commas as
// parsePolicyMetadata splits them. A value containing a comma is read back as two
// entries, which loses what the author wrote but cannot say anything they did not:
// the escaping keeps the whole list on the one line the key introduces.
func (m *metadataComments) setList(key string, values []string) {
	m.set(key, strings.Join(values, ","))
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
//
// A name the policy cannot bind refuses the whole policy, which is what a reader
// that runs it must do; validation reports every one of them and compiles the rest
// (see bindings). A value with no CEL spelling refuses it for the same reason: the
// name would bind something the bundle does not declare (see exprString).
func (p structuredPolicy) wrapVars(body string) (string, error) {
	if len(p.Vars) == 0 {
		return body, nil
	}
	for _, binding := range p.Vars.bindings() {
		if binding.err != nil {
			return "", binding.err
		}
	}
	return nestVars(p.Vars, body)
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
			quoted[i] = celStringLiteral(eco)
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

// celStringLiteral renders an authored value as a CEL string literal, quoted and
// escaped, so a value can only ever be data in the generated expression. It is
// used for the ecosystem guard, which is the one place a policy's own text is
// interpolated into CEL rather than marshaled into it.
//
// Interpolating the value bare let it close the literal and keep going: an
// ecosystems entry of `npm"] || true || ["x"] == ["x` generated a guard that
// matched every ecosystem, so a bundle that reads as scoped to npm denied a PyPI
// package, and it compiled and linted clean. That is the same defect as an aliased
// policy, the text a reviewer reads not being the policy that runs, reached through
// a field instead of a YAML construct.
//
// Go's quoting is CEL's: both accept \\, \", \n, \r, \t, \a, \b, \f, \v, \xHH,
// \uXXXX and \UXXXXXXXX, which is every escape strconv.Quote emits, so the literal
// it produces parses as the value it was given.
func celStringLiteral(value string) string {
	return strconv.Quote(value)
}

// escapeComment escapes an authored value so it stays on the one line of the
// generated `//!` comment that carries it. A newline would end the comment for
// both readers of it, CEL's lexer and parsePolicyMetadata, so a value holding one
// could open a metadata line of its own; a quote would end the value early, and a
// backslash would make either escape ambiguous.
//
// It is reached only through metadataComments, which is what makes the escaping a
// property of writing a metadata line rather than of remembering to call this.
func escapeComment(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	return s
}
