package policy

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/picatz/deputy/internal/collections"
)

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

// EvaluateAll runs all compiled policies against the payload, prefiltering by command/entrypoint when declared.
func (e *Engine) EvaluateAll(ctx context.Context, payload map[string]any, command, entrypoint string) ([]Action, error) {
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
		actions = append(actions, normalized...)
	}
	return actions, nil
}

// shouldSkip determines if a policy should be ignored based on the requested
// command or entrypoint. If the policy defines specific entrypoints or commands,
// it will only run if the request matches one of them.
func shouldSkip(pol compiledPolicy, command, entrypoint string) bool {
	if entrypoint != "" && len(pol.entrypoints) > 0 {
		if _, ok := pol.entrypoints[entrypoint]; !ok {
			return true
		}
	}
	if command != "" && len(pol.commands) > 0 {
		if _, ok := pol.commands[command]; !ok {
			return true
		}
	}
	return false
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
	if val, ok := input["pkg"]; !ok || val == nil {
		if pkg := buildPkgHelper(input); pkg != nil {
			input["pkg"] = pkg
		}
	}
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
		if strings.EqualFold(a.Type, "deny") {
			a.Type = "warn"
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
		missing := parseUndeclared(iss.Err().Error())
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

var undeclaredRe = regexp.MustCompile(`undeclared reference to '([^']+)'`)

// parseUndeclared extracts variable names from CEL compilation errors related
// to undeclared references. This allows the engine to dynamically register
// these variables in the environment.
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
