package policy

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/picatz/deputy/internal/collections"
	"github.com/picatz/deputy/internal/otel"
)

// Evaluator is the interface for evaluating policies against a payload.
// It abstracts the policy engine for consumers that only need evaluation capability.
type Evaluator interface {
	Evaluate(ctx context.Context, entrypoint string, payload map[string]any) ([]Action, error)
}

// Engine holds compiled CEL programs and evaluates them without per-request recompilation.
type Engine struct {
	compiled []compiledPolicy // compiled is the list of pre-compiled policies ready for execution.
}

// compiledPolicy represents a single policy source that has been parsed and
// compiled into an executable CEL program. It includes metadata for filtering
// execution based on entrypoints and commands.
type compiledPolicy struct {
	source      Source                  // source is the original policy source.
	program     celProgram              // program is the compiled CEL executable.
	entrypoints collections.Set[string] // entrypoints is the set of entrypoints this policy applies to.
	commands    collections.Set[string] // commands is the set of commands this policy applies to.
	mode        string                  // mode defines the execution mode (e.g., "enforce", "audit").
}

// celProgram is the minimal interface we need from cel.Program for testing/abstraction.
type celProgram interface {
	ContextEval(context.Context, any) (ref.Val, *cel.EvalDetails, error)
}

// NewEngine builds a compiled engine from already loaded sources.
func NewEngine(sources []Source) (*Engine, error) {
	if len(sources) == 0 {
		return &Engine{}, nil
	}
	compiled := make([]compiledPolicy, 0, len(sources))
	for _, src := range sources {
		prog, err := compileSource(src)
		if err != nil {
			return nil, err
		}
		meta := parsePolicyMetadata(src.Body)
		compiled = append(compiled, compiledPolicy{
			source:      src,
			program:     prog,
			entrypoints: collections.NewSetFunc(meta.Entrypoints, strings.TrimSpace),
			commands:    collections.NewSetFunc(meta.Commands, strings.TrimSpace),
			mode:        meta.Mode,
		})
	}
	return &Engine{compiled: compiled}, nil
}

// NewEngineFromPaths loads sources from disk and builds a compiled engine.
func NewEngineFromPaths(paths []string) (*Engine, error) {
	sources, err := LoadSources(paths)
	if err != nil {
		return nil, err
	}
	return NewEngine(sources)
}

// EvaluateAll runs all compiled policies against the payload and returns aggregated actions.
//
// Policy execution order: Policies are evaluated in the order they were loaded (typically
// the order they appear in source files). Each policy may return zero or more actions.
// All actions from all matching policies are collected and returned.
//
// Filtering behavior: Policies can declare entrypoint and/or command restrictions via metadata.
// A policy is skipped if EITHER:
//   - The policy declares specific entrypoints AND the request entrypoint doesn't match any
//   - The policy declares specific commands AND the request command doesn't match any
//
// This means both filters must pass (AND logic) for a policy to run. Policies without
// restrictions always run.
//
// Advisory mode: Policies with mode="advisory" have their "deny" actions downgraded to "warn",
// allowing observation without blocking.
func (e *Engine) EvaluateAll(ctx context.Context, payload map[string]any, command, entrypoint string) ([]Action, error) {
	startTime := time.Now()
	if e == nil || len(e.compiled) == 0 {
		return nil, nil
	}
	// preserve original map to avoid side effects on callers
	input := cloneMap(payload)
	seedDefaultVariables(input)
	if command != "" || entrypoint != "" {
		env, _ := input["env"].(map[string]any)
		env = maps.Clone(env)
		if env == nil {
			env = map[string]any{}
		}
		if command != "" {
			env["command"] = command
		}
		if entrypoint != "" {
			env["entrypoint"] = entrypoint
		}
		input["env"] = env
	}

	span := otel.SpanFromContext(ctx)
	var actions []Action
	for _, pol := range e.compiled {
		if shouldSkip(pol, command, entrypoint) {
			continue
		}
		out, _, err := pol.program.ContextEval(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pol.source.Name, err)
		}
		val, err := convertRefVal(out)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pol.source.Name, err)
		}
		normalized, err := toActions(pol.source.Name, val)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pol.source.Name, err)
		}
		if strings.EqualFold(pol.mode, "advisory") {
			normalized = downgradeAdvisory(normalized)
		}
		// Record individual policy result as span event
		polResult := "allow"
		for _, a := range normalized {
			if ActionTypeIs(a.Type, ActionDeny) {
				polResult = "deny"
				break
			} else if ActionTypeIs(a.Type, ActionWarn) && polResult == "allow" {
				polResult = "warn"
			}
		}
		otel.RecordPolicyResult(span, pol.source.Name, polResult)
		actions = append(actions, normalized...)
	}

	// Record policy evaluation metrics
	result := "allow"
	for _, a := range actions {
		if ActionTypeIs(a.Type, ActionDeny) {
			result = "deny"
			break
		} else if ActionTypeIs(a.Type, ActionWarn) && result == "allow" {
			result = "warn"
		}
	}
	otel.RecordPolicyEvaluation(ctx, time.Since(startTime).Seconds(), result)

	return actions, nil
}

// Evaluate implements the Evaluator interface. It evaluates all policies against
// the payload using the provided entrypoint, with command inferred from the
// payload's env.command field (if present).
func (e *Engine) Evaluate(ctx context.Context, entrypoint string, payload map[string]any) ([]Action, error) {
	command := ""
	if env, ok := payload["env"].(map[string]any); ok {
		if cmd, ok := env["command"].(string); ok {
			command = cmd
		}
	}
	return e.EvaluateAll(ctx, payload, command, entrypoint)
}

// shouldSkip determines if a policy should be ignored based on the requested
// command or entrypoint.
//
// Skip logic (returns true to skip):
//   - If request has entrypoint AND policy has entrypoint restrictions AND request doesn't match → skip
//   - If request has command AND policy has command restrictions AND request doesn't match → skip
//   - Otherwise → don't skip (run the policy)
//
// This implements AND semantics: BOTH command and entrypoint filters must pass for the policy to run.
// Policies without restrictions (empty entrypoints/commands lists) always pass their respective checks.
func shouldSkip(pol compiledPolicy, command, entrypoint string) bool {
	// Check entrypoint filter
	if entrypoint != "" && len(pol.entrypoints) > 0 {
		if _, ok := pol.entrypoints[entrypoint]; !ok {
			return true // Entrypoint doesn't match policy's allowed entrypoints
		}
	}
	// Check command filter
	if command != "" && len(pol.commands) > 0 {
		if _, ok := pol.commands[command]; !ok {
			return true // Command doesn't match policy's allowed commands
		}
	}
	return false // All filters passed, run the policy
}

// seedDefaultVariables ensures that standard variables expected by policies
// are present in the input map. It populates missing variables with nil or
// default values to prevent runtime errors during CEL evaluation.
func seedDefaultVariables(input map[string]any) {
	if input == nil {
		return
	}
	for _, name := range defaultVariableNames {
		if _, ok := input[name]; !ok {
			input[name] = nil
		}
	}
	if target := buildTargetHelper(input); target != nil {
		input["target"] = target
	}
	if image := buildImageHelper(input); image != nil {
		input["image"] = image
	}
	if val, ok := input["pkg"]; !ok || val == nil {
		if pkg := buildPkgHelper(input); pkg != nil {
			input["pkg"] = pkg
		}
	}
	// Inject constant objects for cleaner policy authoring
	input["severity"] = severityConstants
	input["scope"] = scopeConstants
}

// downgradeAdvisory converts "deny" actions to "warn" actions for policies
// running in advisory mode. This allows policies to report violations without
// blocking execution.
func downgradeAdvisory(actions []Action) []Action {
	if len(actions) == 0 {
		return actions
	}
	out := make([]Action, len(actions))
	for i, a := range actions {
		if ActionTypeIs(a.Type, ActionDeny) {
			a.Type = ActionWarn
			a.Status = nil
			if strings.TrimSpace(a.Reason) == "" {
				a.Reason = "advisory policy (originally deny)"
			}
		}
		out[i] = a
	}
	return out
}

// compileSource compiles a raw policy source into a CEL program. It handles
// dynamic environment generation by detecting undeclared variables and
// recompiling with the necessary context.
func compileSource(src Source) (celProgram, error) {
	env, err := envWithNames(nil)
	if err != nil {
		return nil, err
	}
	ast, iss := env.Compile(src.Body)
	if iss != nil && iss.Err() != nil {
		missing := parseUndeclaredFromIssues(iss)
		if len(missing) == 0 {
			return nil, fmt.Errorf("%s: %w", src.Name, iss.Err())
		}
		env, err = envWithNames(missing)
		if err != nil {
			return nil, err
		}
		ast, iss = env.Compile(src.Body)
		if iss != nil && iss.Err() != nil {
			return nil, fmt.Errorf("%s: %w", src.Name, iss.Err())
		}
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src.Name, err)
	}
	return prog, nil
}

// undeclaredRe matches CEL "undeclared reference" error messages.
// The pattern captures the variable name from messages like:
//
//	"undeclared reference to 'foo'"
//	"undeclared reference to 'foo' (in container '')"
var undeclaredRe = regexp.MustCompile(`undeclared reference to '([^']+)'`)

// parseUndeclaredFromIssues extracts undeclared variable names by iterating
// through individual CEL compilation errors. This is more robust than parsing
// the full error string because it accesses each error's Message field directly.
func parseUndeclaredFromIssues(iss *cel.Issues) []string {
	if iss == nil {
		return nil
	}
	errs := iss.Errors()
	if len(errs) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, e := range errs {
		names := parseUndeclared(e.Message)
		for _, name := range names {
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				out = append(out, name)
			}
		}
	}
	return out
}

// parseUndeclared extracts variable names from a CEL error message string.
// It handles the standard CEL undeclared reference format:
//
//	"undeclared reference to 'varname'"
//	"undeclared reference to 'varname' (in container '')"
func parseUndeclared(msg string) []string {
	matches := undeclaredRe.FindAllStringSubmatch(msg, -1)
	var out []string
	for _, m := range matches {
		if len(m) == 2 {
			out = append(out, m[1])
		}
	}
	return out
}

// cloneMap shallow-copies a map[string]any.
func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return maps.Clone(m)
}
