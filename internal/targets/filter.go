package targets

import (
	"context"
	"fmt"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
)

// FilterDiscoveredTargets filters a slice of discovered targets using a CEL expression.
// The expression has access to:
//   - uri: string - the target URI
//   - name: string - the target name
//   - description: string - the target description
//   - created_at: timestamp - when the target was created (may be zero)
//   - metadata: map[string]string - provider-specific attributes
//
// Example expressions:
//   - 'metadata["tags.env"] == "prod"'
//   - 'name.startsWith("web-") && created_at > timestamp("2024-01-01T00:00:00Z")'
//   - 'uri.contains("us-west-2")'
func FilterDiscoveredTargets(ctx context.Context, targets []*listv1.DiscoveredTarget, filter string) ([]*listv1.DiscoveredTarget, error) {
	if filter == "" {
		return targets, nil
	}

	prog, err := compileTargetFilter(filter)
	if err != nil {
		return nil, fmt.Errorf("compile filter: %w", err)
	}

	result := make([]*listv1.DiscoveredTarget, 0, len(targets))
	for _, t := range targets {
		match, err := evalTargetFilter(ctx, prog, t)
		if err != nil {
			return nil, fmt.Errorf("evaluate filter for %q: %w", t.GetUri(), err)
		}
		if match {
			result = append(result, t)
		}
	}
	return result, nil
}

// ValidateTargetFilter validates a CEL filter expression without executing it.
// Returns nil if the expression is valid, or an error describing the problem.
func ValidateTargetFilter(filter string) error {
	if filter == "" {
		return nil
	}
	_, err := compileTargetFilter(filter)
	return err
}

// targetFilterEnv is the CEL environment for target filtering.
// It's created lazily and reused for all filter compilations.
var targetFilterEnv *cel.Env

func getTargetFilterEnv() (*cel.Env, error) {
	if targetFilterEnv != nil {
		return targetFilterEnv, nil
	}

	env, err := cel.NewEnv(
		// Declare the variables available to filter expressions
		cel.Variable("uri", cel.StringType),
		cel.Variable("name", cel.StringType),
		cel.Variable("description", cel.StringType),
		cel.Variable("created_at", cel.TimestampType),
		cel.Variable("metadata", cel.MapType(cel.StringType, cel.StringType)),

		// Include useful extensions
		ext.Strings(), // contains, startsWith, endsWith, etc.
		ext.Lists(),   // list operations
		ext.Math(),    // mathematical functions

		// Enable optional types for safe null handling
		cel.OptionalTypes(),
	)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}

	targetFilterEnv = env
	return env, nil
}

// compileTargetFilter compiles a CEL expression for target filtering.
func compileTargetFilter(filter string) (cel.Program, error) {
	env, err := getTargetFilterEnv()
	if err != nil {
		return nil, err
	}

	ast, issues := env.Compile(filter)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("parse filter: %w", issues.Err())
	}

	// Ensure the expression returns a boolean
	if ast.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("filter must return a boolean, got %s", ast.OutputType())
	}

	prog, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("compile filter program: %w", err)
	}

	return prog, nil
}

// evalTargetFilter evaluates a compiled filter against a discovered target.
func evalTargetFilter(ctx context.Context, prog cel.Program, target *listv1.DiscoveredTarget) (bool, error) {
	if target == nil {
		return false, nil
	}

	// Build the input map for CEL evaluation
	input := map[string]any{
		"uri":         target.GetUri(),
		"name":        target.GetName(),
		"description": target.GetDescription(),
		"metadata":    target.GetMetadata(),
	}

	// Handle created_at timestamp
	if target.GetCreatedAt() != nil {
		input["created_at"] = target.GetCreatedAt().AsTime()
	} else {
		// Use zero time if not set
		input["created_at"] = time.Time{}
	}

	// Handle nil metadata
	if input["metadata"] == nil {
		input["metadata"] = map[string]string{}
	}

	out, _, err := prog.ContextEval(ctx, input)
	if err != nil {
		return false, fmt.Errorf("eval: %w", err)
	}

	// Convert result to bool
	return celToBool(out)
}

// celToBool converts a CEL value to a Go bool.
func celToBool(val ref.Val) (bool, error) {
	if val == nil {
		return false, nil
	}

	switch v := val.(type) {
	case types.Bool:
		return bool(v), nil
	default:
		// Try native conversion
		if native, ok := val.Value().(bool); ok {
			return native, nil
		}
		return false, fmt.Errorf("expected bool, got %T", val.Value())
	}
}
