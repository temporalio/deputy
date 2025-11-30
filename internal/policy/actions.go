package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/google/cel-go/common/types/ref"
)

// Action represents a normalized policy decision emitted by a CEL program.
type Action struct {
	Source      string
	Type        string
	Reason      string
	Message     string
	Remediation string
	Code        string
	Status      *int
	Headers     map[string]string
	Annotations map[string]any
	Raw         map[string]any
}

// EvaluateAll executes every policy source against the provided input and
// aggregates the resulting actions.
func EvaluateAll(ctx context.Context, sources []Source, input map[string]any) ([]Action, error) {
	if len(sources) == 0 {
		return nil, nil
	}
	var actions []Action
	for _, src := range sources {
		val, err := Evaluate(ctx, src.Body, input)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src.Name, err)
		}
		normalized, err := toActions(src.Name, val)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src.Name, err)
		}
		actions = append(actions, normalized...)
	}
	return actions, nil
}

func toActions(source string, value any) ([]Action, error) {
	if value == nil {
		return nil, nil
	}
	switch v := value.(type) {
	case []any:
		var out []Action
		for idx, elem := range v {
			act, err := toAction(source, elem)
			if err != nil {
				return nil, fmt.Errorf("action[%d]: %w", idx, err)
			}
			if act != nil {
				out = append(out, *act)
			}
		}
		return out, nil
	case map[string]any:
		act, err := toAction(source, v)
		if err != nil {
			return nil, err
		}
		if act == nil {
			return nil, nil
		}
		return []Action{*act}, nil
	default:
		return nil, fmt.Errorf("policies must return an object or list of objects, got %T", value)
	}
}

func toAction(source string, value any) (*Action, error) {
	if value == nil {
		return nil, nil
	}
	switch v := value.(type) {
	case Action:
		return &v, nil
	case map[string]any:
		actType, _ := getString(v, "action")
		if strings.TrimSpace(actType) == "" {
			// allow returning raw annotations without action
			return nil, nil
		}
		act := Action{
			Source: source,
			Type:   strings.ToLower(strings.TrimSpace(actType)),
			Raw:    v,
		}
		act.Reason, _ = getString(v, "reason")
		act.Message, _ = getString(v, "message")
		act.Remediation, _ = getString(v, "remediation")
		act.Code, _ = getString(v, "code")
		if statusVal, ok := v["status"]; ok {
			if n, ok := statusVal.(float64); ok {
				s := int(n)
				act.Status = &s
			} else if n, ok := statusVal.(int); ok {
				act.Status = &n
			} else if n, ok := statusVal.(json.Number); ok {
				if i, err := n.Int64(); err == nil {
					s := int(i)
					act.Status = &s
				}
			}
		}
		if headersRaw, ok := v["headers"].(map[string]any); ok {
			act.Headers = make(map[string]string, len(headersRaw))
			for k, val := range headersRaw {
				act.Headers[k] = fmt.Sprint(val)
			}
		}
		if annRaw, ok := v["annotations"].(map[string]any); ok {
			act.Annotations = annRaw
		}
		return &act, nil
	case map[ref.Val]ref.Val:
		native, err := convertRefMap(v)
		if err != nil {
			return nil, err
		}
		return toAction(source, native)
	case ref.Val:
		native, err := convertRefVal(v)
		if err != nil {
			return nil, err
		}
		return toAction(source, native)
	default:
		return nil, fmt.Errorf("unexpected action type %T", value)
	}
}

func getString(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	switch val := v.(type) {
	case string:
		return val, true
	case fmt.Stringer:
		return val.String(), true
	case json.Number:
		return val.String(), true
	case float64:
		if math.IsNaN(val) {
			return "", false
		}
		return fmt.Sprint(val), true
	default:
		return fmt.Sprint(val), true
	}
}

func convertRefMap(m map[ref.Val]ref.Val) (map[string]any, error) {
	out := make(map[string]any, len(m))
	for k, v := range m {
		ks, err := convertRefVal(k)
		if err != nil {
			return nil, err
		}
		kstr, ok := ks.(string)
		if !ok {
			return nil, fmt.Errorf("policy output map keys must be strings, got %T", ks)
		}
		val, err := convertRefVal(v)
		if err != nil {
			return nil, err
		}
		out[kstr] = val
	}
	return out, nil
}
