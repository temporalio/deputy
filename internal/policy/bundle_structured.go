package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

type structuredBundle struct {
	APIVersion string             `yaml:"apiVersion"`
	Kind       string             `yaml:"kind"`
	Metadata   map[string]any     `yaml:"metadata,omitempty"`
	Policies   []structuredPolicy `yaml:"policies"`
}

type structuredPolicy struct {
	Name        string           `yaml:"name"`
	Description string           `yaml:"description,omitempty"`
	Ecosystems  []string         `yaml:"ecosystems,omitempty"`
	Vars        orderedVars      `yaml:"vars,omitempty"`
	Rules       []structuredRule `yaml:"rules"`
}

// orderedVars preserves author order from YAML mappings so dependent vars
// expand deterministically (later vars can reference earlier ones).
type orderedVars []varKV

type varKV struct {
	Name string
	Expr string
}

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
		if err := v.Decode(&kv.Expr); err != nil {
			return err
		}
		out = append(out, kv)
	}
	*o = out
	return nil
}

func (o *orderedVars) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]varKV, 0, len(keys))
	for _, k := range keys {
		out = append(out, varKV{Name: k, Expr: m[k]})
	}
	*o = out
	return nil
}

type structuredRule struct {
	Action      string            `yaml:"action"`
	When        string            `yaml:"when"`
	Reason      string            `yaml:"reason,omitempty"`
	Status      *int              `yaml:"status,omitempty"`
	Headers     map[string]string `yaml:"headers,omitempty"`
	Remediation string            `yaml:"remediation,omitempty"`
	Details     map[string]any    `yaml:"details,omitempty"`
}

const structuredAPIVersion = "policy.deputy.sh/v1alpha2"

func tryParseStructuredBundle(data []byte, path string) ([]Source, bool, error) {
	var bundle structuredBundle
	if err := yaml.Unmarshal(data, &bundle); err != nil {
		trim := strings.TrimSpace(string(data))
		if strings.HasPrefix(trim, "apiVersion") || strings.Contains(trim, "apiVersion:") {
			return nil, false, fmt.Errorf("%s: parse structured bundle: %w", path, err)
		}
		return nil, false, nil
	}
	if strings.TrimSpace(bundle.APIVersion) == "" || len(bundle.Policies) == 0 {
		return nil, false, nil
	}
	if bundle.APIVersion != structuredAPIVersion {
		return nil, false, fmt.Errorf("%s: unsupported apiVersion %q", path, bundle.APIVersion)
	}
	if bundle.Kind != "PolicyBundle" && bundle.Kind != "" {
		return nil, false, fmt.Errorf("%s: unsupported kind %q", path, bundle.Kind)
	}
	var sources []Source
	for _, pol := range bundle.Policies {
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

func (p structuredPolicy) toCELSource() (string, error) {
	if len(p.Rules) == 0 {
		return "[]", nil
	}
	var builder strings.Builder
	builder.WriteString("[]")
	for _, rule := range p.Rules {
		expr, err := rule.toRuleExpr(p.Ecosystems)
		if err != nil {
			return "", err
		}
		builder.WriteString(" + ")
		builder.WriteString(expr)
	}
	body := builder.String()
	if len(p.Vars) > 0 {
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
		// expand vars in reverse author order so earlier vars are in scope for later ones
		for i := len(p.Vars) - 1; i >= 0; i-- {
			name := p.Vars[i].Name
			expr := p.Vars[i].Expr
			body = fmt.Sprintf("([%s]).map(%s, %s)[0]", expr, name, body)
		}
	}
	metadata := []string{}
	if p.Name != "" {
		metadata = append(metadata, fmt.Sprintf("//! policy.name = \"%s\"", escapeComment(p.Name)))
	}
	if p.Description != "" {
		metadata = append(metadata, fmt.Sprintf("//! policy.description = \"%s\"", escapeComment(p.Description)))
	}
	if len(p.Ecosystems) > 0 {
		metadata = append(metadata, fmt.Sprintf("//! policy.ecosystems = \"%s\"", strings.Join(p.Ecosystems, ",")))
	}
	if len(metadata) == 0 {
		return body, nil
	}
	return strings.Join(metadata, "\n") + "\n" + body, nil
}

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
		when = fmt.Sprintf("((request.ecosystem in [%s]) && (%s))", strings.Join(quoted, ","), when)
	}
	if strings.TrimSpace(r.Action) == "" {
		return "", fmt.Errorf("rule missing action")
	}
	action := map[string]any{"action": r.Action}
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

func escapeComment(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}
