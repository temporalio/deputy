package policy

import (
	"context"
	"fmt"
	"reflect"
	"sort"
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

// Evaluate compiles the provided CEL source and evaluates it against the input
// document. Input keys are exposed to the CEL program as top-level identifiers.
func Evaluate(ctx context.Context, source string, input map[string]any) (any, error) {
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

func envForInput(input map[string]any) (*cel.Env, error) {
	var extra []string
	for name := range input {
		extra = append(extra, name)
	}
	return envWithNames(extra)
}

func envWithNames(extra []string) (*cel.Env, error) {
	vars := make(map[string]struct{}, len(extra)+len(defaultVariableNames))
	for _, name := range defaultVariableNames {
		vars[name] = struct{}{}
	}
	for _, name := range extra {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		vars[name] = struct{}{}
	}
	names := make([]string, 0, len(vars))
	for name := range vars {
		names = append(names, name)
	}
	sort.Strings(names)
	declSlice := make([]*exprpb.Decl, 0, len(names))
	for _, name := range names {
		declSlice = append(declSlice, decls.NewVar(name, decls.Dyn))
	}
	env, err := cel.NewEnv(
		cel.OptionalTypes(),
		cel.Declarations(declSlice...),
		ext.Strings(),
		ext.Lists(),
		ext.Sets(),
		ext.Regex(),
	)
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
	} else if req, ok := input["request"].(map[string]any); ok {
		src = req
	} else {
		return nil
	}
	pkg := map[string]any{}
	if name, ok := src["package"]; ok {
		pkg["name"] = name
	} else if name, ok := src["module"]; ok {
		pkg["name"] = name
	} else if name, ok := src["name"]; ok {
		pkg["name"] = name
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
