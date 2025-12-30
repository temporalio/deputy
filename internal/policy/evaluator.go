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
		"jwt", // JWT claims from authenticated proxy requests
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
	seedDefaultVariables(input)
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
	return envWithNames(slices.Collect(maps.Keys(input)))
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
		// Standard extensions
		ext.Strings(),
		ext.Lists(),
		ext.Sets(),
		ext.Regex(),
		// Additional extensions for richer policy expressions
		ext.Bindings(), // cel.bind() for local variables
		ext.Encoders(), // base64.encode/decode
		ext.Math(),     // math functions (abs, ceil, floor, etc.)
	}
	opts = append(opts, customHelperFunctions()...)
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("build CEL env: %w", err)
	}
	return env, nil
}

// buildPkgHelper synthesizes a unified package view from common input shapes.
// It always returns a map with sensible defaults for optional fields so that
// policy authors can write simpler expressions without excessive ?.orValue() usage:
//   - name defaults to "" (empty string)
//   - licenses defaults to [] (empty list)
//   - version defaults to "" (empty string)
//   - ecosystem defaults to "" (empty string)
//
// This allows policies like `pkg.licenses.exists(l, l == "GPL-3.0")` to work
// without needing `pkg.?licenses.orValue([]).exists(...)`.
//
// Policies that need to guard against "no package data" can check `pkg.name == ""`
// or use entrypoint filtering to only run when package data is expected.
func buildPkgHelper(input map[string]any) map[string]any {
	// Initialize with sensible defaults for all fields.
	// This simplifies policy expressions by eliminating ?.orValue() boilerplate.
	pkg := map[string]any{
		"name":      "",
		"licenses":  []any{},
		"version":   "",
		"ecosystem": "",
	}

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
		return pkg
	}

	// Try various keys for the package name
	if name, ok := src["package"]; ok {
		pkg["name"] = name
	}
	if pkg["name"] == "" {
		if name, ok := src["module"]; ok {
			pkg["name"] = name
		}
	}
	if pkg["name"] == "" {
		if name, ok := src["name"]; ok {
			pkg["name"] = name
		}
	}

	// Override defaults with actual values if present
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
	// Pre-allocate two rows and swap them to avoid allocations per iteration
	prev := make([]int64, len(a)+1)
	curr := make([]int64, len(a)+1)
	for i := range prev {
		prev[i] = int64(i)
	}
	for j := 1; j <= len(b); j++ {
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
		prev, curr = curr, prev
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
