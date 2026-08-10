package policy

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/google/cel-go/common/types/ref"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	"github.com/temporalio/deputy/internal/collections"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Action type constants are the canonical spelling of each
// deputy.policy.v1.ActionType value, which is what policies write and what the
// engine switches on. They are constants because callers need them at compile
// time; TestActionTypesMatchProtoDescriptor pins them to the enum so a rename in
// the proto cannot leave them behind.
const (
	// ActionDeny blocks the operation and returns an error to the caller.
	ActionDeny = "deny"

	// ActionWarn allows the operation but emits a warning message.
	ActionWarn = "warn"

	// ActionAllow explicitly permits the operation (no effect if other rules deny).
	ActionAllow = "allow"
)

// actionTypePrefix is the generated enum's value prefix. Policies write the bare
// action ("deny"), not the proto spelling.
const actionTypePrefix = "ACTION_TYPE_"

// actionTypes is the action vocabulary derived from the generated ActionType
// descriptor.
var actionTypes = newActionVocabulary()

// newActionVocabulary reads the deputy.policy.v1.ActionType descriptor once at
// startup and returns the actions a policy may write, lowercased and ordered by
// enum number so messages read the same way every time. Deriving the list means
// the proto stays the single source of truth for the vocabulary. The zero value
// is skipped: UNSPECIFIED means no action was set, which is not something an
// author can ask for.
func newActionVocabulary() []string {
	values := policyv1.ActionType(0).Descriptor().Values()
	byNumber := make([]protoreflect.EnumValueDescriptor, 0, values.Len())
	for i := range values.Len() {
		if value := values.Get(i); value.Number() != 0 {
			byNumber = append(byNumber, value)
		}
	}
	slices.SortFunc(byNumber, func(a, b protoreflect.EnumValueDescriptor) int {
		return cmp.Compare(a.Number(), b.Number())
	})
	names := make([]string, 0, len(byNumber))
	for _, value := range byNumber {
		names = append(names, strings.ToLower(strings.TrimPrefix(string(value.Name()), actionTypePrefix)))
	}
	return names
}

// ActionTypeIs returns true if the action type matches the expected type (case-insensitive).
func ActionTypeIs(actionType, expected string) bool {
	return strings.EqualFold(actionType, expected)
}

// ActionTypes returns the action vocabulary a policy rule may emit, in the order
// used by error messages and editor surfaces. The slice is freshly allocated so
// callers cannot mutate the vocabulary.
func ActionTypes() []string {
	return slices.Clone(actionTypes)
}

// NormalizeActionType folds an authored action value into its canonical form by
// trimming surrounding whitespace and lowercasing it. "DENY", "Deny" and " deny "
// all mean deny: evaluation already compares action types case-insensitively
// (see ActionTypeIs), so parsing accepts exactly what the runtime accepts and
// everything downstream sees the canonical lowercase spelling. This mirrors how
// a policy's mode field is normalized before validation.
func NormalizeActionType(actionType string) string {
	return strings.ToLower(strings.TrimSpace(actionType))
}

// ValidateActionType returns the canonical form of an authored action value, or
// an error naming the offending value and the valid vocabulary. A typo such as
// "dney" is otherwise accepted verbatim and yields a rule that can never deny
// anything, so an unknown action must fail at load time instead of degrading
// into a silently permissive rule.
func ValidateActionType(actionType string) (string, error) {
	normalized := NormalizeActionType(actionType)
	if slices.Contains(actionTypes, normalized) {
		return normalized, nil
	}
	return "", fmt.Errorf("invalid action %q (expected %s)", actionType, strings.Join(actionTypes, "|"))
}

// Action represents a normalized policy decision emitted by a CEL program.
type Action struct {
	Source      string            // Source is the name of the policy that generated this action.
	Type        string            // Type is the action type (e.g., "deny", "warn", "allow").
	Reason      string            // Reason is a human-readable explanation for the action.
	Message     string            // Message is an optional additional message.
	Remediation string            // Remediation suggests how to resolve the issue.
	Code        string            // Code is a machine-readable error code.
	Status      *int              // Status is an optional HTTP status code to return.
	Headers     map[string]string // Headers are HTTP headers to set in the response.
	Annotations map[string]any    // Annotations are arbitrary metadata attached to the action.
	Raw         map[string]any    // Raw is the original map returned by the policy.
}

// EvaluateAll executes every policy source against the provided input proto
// and aggregates the resulting actions.
func EvaluateAll(ctx context.Context, sources []Source, input proto.Message) ([]Action, error) {
	eng, err := NewEngine(sources)
	if err != nil {
		return nil, err
	}
	return eng.EvaluateAll(ctx, input, "", "")
}

// EvaluateMap executes policies against a raw map[string]any input.
// This is intended for CLI testing scenarios where the input is arbitrary JSON
// rather than a typed proto message. For production use, prefer EvaluateAll
// with typed proto inputs.
func EvaluateMap(ctx context.Context, sources []Source, input map[string]any) ([]Action, error) {
	eng, err := NewEngine(sources)
	if err != nil {
		return nil, err
	}
	return eng.EvaluateAllMap(ctx, input, "", "")
}

// toActions converts a raw policy result (map or list of maps) into a slice of Action structs.
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

// toAction converts a single raw policy result map into an Action struct.
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
			Type:   collections.NormalizeLower(actType),
			Raw:    v,
		}
		act.Reason, _ = getString(v, "reason")
		act.Message, _ = getString(v, "message")
		act.Remediation, _ = getString(v, "remediation")
		act.Code, _ = getString(v, "code")
		if statusVal, ok := v["status"]; ok {
			switch n := statusVal.(type) {
			case float64:
				s := int(n)
				act.Status = &s
			case int:
				act.Status = &n
			case json.Number:
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

// getString safely retrieves a string value from a map[string]any, handling various types.
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
	case float64:
		if math.IsNaN(val) {
			return "", false
		}
		return fmt.Sprint(val), true
	default:
		return fmt.Sprint(val), true
	}
}

// convertRefMap converts a CEL map[ref.Val]ref.Val to a native map[string]any.
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
