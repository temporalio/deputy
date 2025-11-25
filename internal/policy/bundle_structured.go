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
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Ecosystems  []string          `yaml:"ecosystems,omitempty"`
	Vars        map[string]string `yaml:"vars,omitempty"`
	Rules       []structuredRule  `yaml:"rules"`
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
		keys := make([]string, 0, len(p.Vars))
		for k := range p.Vars {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i := len(keys) - 1; i >= 0; i-- {
			name := keys[i]
			expr := p.Vars[name]
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
