package policy

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	anyType = reflect.TypeOf((*any)(nil)).Elem()

	defaultVariableNames = []string{
		"pkg",
		"request",
		"vulnerabilities",
		"vulnerability",
		"changes",
		"packages",
		"sbom",
		"config",
		"env",
		"dependency",
		"plan",
		"step",
		"repo",
		"cluster",
		"component",
		"findings",
		"change",
	}
)

// DefaultVariableNames returns the identifiers that Deputy injects into CEL
// environments for policies. Tooling (e.g., LSP) uses this to stay aligned with
// the runtime without duplicating the list.
func DefaultVariableNames() []string {
	return slices.Clone(defaultVariableNames)
}

// Evaluate compiles the provided CEL source and evaluates it against the input
// document. Input keys are exposed to the CEL program as top-level identifiers.
func Evaluate(ctx context.Context, source string, input map[string]any) (any, error) {
	// Clone input to avoid side effects on the caller's map.
	input = maps.Clone(input)
	if input == nil {
		input = map[string]any{}
	}
	for _, name := range defaultVariableNames {
		if _, ok := input[name]; !ok {
			input[name] = nil
		}
	}
	if val, ok := input["pkg"]; !ok || val == nil {
		if pkg := buildPkgHelper(input); pkg != nil {
			input["pkg"] = pkg
		}
	}
	env, err := envForInput(input)
	if err != nil {
		return nil, err
	}
	ast, iss := env.Compile(source)
	if iss != nil && iss.Err() != nil {
		return nil, iss.Err()
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, err
	}
	out, _, err := prog.ContextEval(ctx, input)
	if err != nil {
		return nil, err
	}
	return convertRefVal(out)
}

// Compile verifies that the CEL source parses and type-checks using the
// provided extra variable names (in addition to the default policy variables).
func Compile(source string, extraVars []string) error {
	env, err := envWithNames(extraVars)
	if err != nil {
		return err
	}
	_, iss := env.Compile(source)
	if iss != nil && iss.Err() != nil {
		return iss.Err()
	}
	return nil
}

// envForInput creates a CEL environment configured with variables derived from the input map keys.
func envForInput(input map[string]any) (*cel.Env, error) {
	var extra []string
	for name := range input {
		extra = append(extra, name)
	}
	return envWithNames(extra)
}

// envWithNames creates a CEL environment with the default variables plus any extra variables provided.
func envWithNames(extra []string) (*cel.Env, error) {
	names := slices.Concat(defaultVariableNames, extra)
	slices.Sort(names)
	names = slices.Compact(names)

	// Filter out empty strings and create declarations
	declSlice := make([]*exprpb.Decl, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		declSlice = append(declSlice, decls.NewVar(name, decls.Dyn))
	}
	opts := []cel.EnvOption{
		cel.OptionalTypes(),
		cel.Declarations(declSlice...),
		ext.Strings(),
		ext.Lists(),
		ext.Sets(),
		ext.Regex(),
	}
	opts = append(opts, customHelperFunctions()...)
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("build CEL env: %w", err)
	}
	return env, nil
}

// buildPkgHelper synthesizes a unified package view from common input shapes.
// If no recognizable package data is present, it returns nil.
func buildPkgHelper(input map[string]any) map[string]any {
	// Prefer component (sbom/diff) then request (proxy)
	var src map[string]any
	if comp, ok := input["component"].(map[string]any); ok {
		src = comp
	}
	if src == nil {
		if req, ok := input["request"].(map[string]any); ok {
			src = req
		}
	}
	if src == nil {
		return nil
	}

	pkg := map[string]any{}
	// Try various keys for the package name
	if name, ok := src["package"]; ok {
		pkg["name"] = name
	}
	if _, ok := pkg["name"]; !ok {
		if name, ok := src["module"]; ok {
			pkg["name"] = name
		}
	}
	if _, ok := pkg["name"]; !ok {
		if name, ok := src["name"]; ok {
			pkg["name"] = name
		}
	}

	if ver, ok := src["version"]; ok {
		pkg["version"] = ver
	}
	if eco, ok := src["ecosystem"]; ok {
		pkg["ecosystem"] = eco
	}
	if lic, ok := src["licenses"]; ok {
		pkg["licenses"] = lic
	}
	return pkg
}

// convertRefVal converts a CEL ref.Val to a native Go value.
func convertRefVal(val ref.Val) (any, error) {
	if val == nil {
		return nil, nil
	}
	switch v := val.Value().(type) {
	case []ref.Val:
		out := make([]any, len(v))
		for i, elem := range v {
			converted, err := convertRefVal(elem)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case map[ref.Val]ref.Val:
		out := make(map[string]any, len(v))
		for mk, mv := range v {
			keyVal, err := convertRefVal(mk)
			if err != nil {
				return nil, err
			}
			keyStr, ok := keyVal.(string)
			if !ok {
				return nil, fmt.Errorf("policy output map keys must be strings, got %T", keyVal)
			}
			valVal, err := convertRefVal(mv)
			if err != nil {
				return nil, err
			}
			out[keyStr] = valVal
		}
		return out, nil
	default:
		if native, err := val.ConvertToNative(anyType); err == nil {
			return native, nil
		}
		return nil, fmt.Errorf("unable to convert CEL value of type %T", val.Value())
	}
}

// levenshtein computes the Levenshtein distance between a and b with an optional
// maxLen cap (rejects if either input exceeds cap by returning -1) and an early
// exit limit (stop when distance already exceeds limit; pass -1 for no early exit).
func levenshtein(a, b string, maxLen int, limit int64) int64 {
	if maxLen > 0 && (len(a) > maxLen || len(b) > maxLen) {
		return -1
	}
	if a == b {
		return 0
	}
	if len(a) == 0 {
		return int64(len(b))
	}
	if len(b) == 0 {
		return int64(len(a))
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	prev := make([]int64, len(a)+1)
	for i := range prev {
		prev[i] = int64(i)
	}
	for j := 1; j <= len(b); j++ {
		curr := make([]int64, len(a)+1)
		curr[0] = int64(j)
		minRow := curr[0]
		bc := b[j-1]
		for i := 1; i <= len(a); i++ {
			cost := int64(0)
			if a[i-1] != bc {
				cost = 1
			}
			del := prev[i] + 1
			ins := curr[i-1] + 1
			sub := prev[i-1] + cost
			curr[i] = minInt64(del, ins, sub)
			if curr[i] < minRow {
				minRow = curr[i]
			}
		}
		if limit >= 0 && minRow > limit {
			return minRow
		}
		prev = curr
	}
	if limit >= 0 && prev[len(a)] > limit {
		return prev[len(a)]
	}
	return prev[len(a)]
}

// minInt64 returns the minimum value from a list of int64s.
func minInt64(vals ...int64) int64 {
	if len(vals) == 0 {
		return 0
	}
	m := vals[0]
	for _, v := range vals[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

// toString safely converts a CEL ref.Val to a string.
func toString(v ref.Val) string {
	if v == nil {
		return ""
	}
	switch t := v.Value().(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	default:
		return fmt.Sprint(t)
	}
}

// toInt64 safely converts a CEL ref.Val to an int64.
func toInt64(v ref.Val) int64 {
	if v == nil {
		return 0
	}
	switch t := v.Value().(type) {
	case int64:
		return t
	case int32:
		return int64(t)
	case int:
		return int64(t)
	case uint64:
		return int64(t)
	case uint32:
		return int64(t)
	case float64:
		return int64(t)
	case float32:
		return int64(t)
	default:
		return 0
	}
}
