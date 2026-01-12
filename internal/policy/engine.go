package policy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/picatz/deputy/gen/deputy/policy/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
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

		// Validate entrypoints at load time - reject unknown entrypoints
		if err := validateEntrypoints(meta.Entrypoints, src.Name); err != nil {
			return nil, err
		}

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

// validateEntrypoints checks that all entrypoints are known canonical values.
// This prevents typos and injection of arbitrary entrypoint names.
func validateEntrypoints(entrypoints []string, policyName string) error {
	for _, ep := range entrypoints {
		ep = strings.TrimSpace(ep)
		if ep == "" {
			continue
		}
		if !IsAllowedEntrypoint(ep) {
			return fmt.Errorf("%s: invalid entrypoint %q (not in allowed set)", policyName, ep)
		}
	}
	return nil
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
	// Validate entrypoint at evaluation time if provided
	if entrypoint != "" && !IsAllowedEntrypoint(entrypoint) {
		return nil, fmt.Errorf("invalid entrypoint: %q", entrypoint)
	}

	// preserve original map to avoid side effects on callers - use deep clone
	input := deepCloneMap(payload)
	seedDefaultVariables(input)
	if command != "" || entrypoint != "" {
		env, _ := input["env"].(map[string]any)
		env = deepCloneMap(env)
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
	// Inject constant objects for cleaner policy authoring
	input["severity"] = severityConstants
	input["scope"] = scopeConstants

	// Synthesize pkg from component or request for policies that use
	// pkg.name, pkg.version, pkg.ecosystem, pkg.licenses, etc.
	if input["pkg"] == nil {
		input["pkg"] = buildPkgFromInput(input)
	}

	// Always synthesize image from target and image_info for policies that use
	// image.image (reference), image.config, image.metadata, image.history, etc.
	// This combines the image reference from target with configuration from ImageInfo.
	if img := buildImageFromInput(input); len(img) > 0 {
		input["image"] = img
	}
}

// buildPkgFromInput synthesizes a Package proto from component or request data
// in the input map. Returns a Package with fields populated from whichever
// source is available (component takes precedence over request).
func buildPkgFromInput(input map[string]any) *dependencyv1.Package {
	// Default empty package - CEL will see zero values for all fields
	pkg := &dependencyv1.Package{}

	// Try component first (sbom, diff entrypoints)
	if comp := input["component"]; comp != nil {
		switch c := comp.(type) {
		case *dependencyv1.Package:
			return c
		case map[string]any:
			if name, ok := c["name"].(string); ok {
				pkg.Name = name
			}
			if version, ok := c["version"].(string); ok {
				pkg.Version = version
			}
			if ecosystem, ok := c["ecosystem"].(string); ok {
				pkg.Ecosystem = ecosystem
			}
			if licenses, ok := c["licenses"].([]string); ok {
				pkg.Licenses = licenses
			} else if licenses, ok := c["licenses"].([]any); ok {
				for _, l := range licenses {
					if s, ok := l.(string); ok {
						pkg.Licenses = append(pkg.Licenses, s)
					}
				}
			}
			return pkg
		}
	}

	// Try request (proxy entrypoints)
	if req := input["request"]; req != nil {
		switch r := req.(type) {
		case *policyv1.ProxyRequest:
			pkg.Name = r.Package
			if pkg.Name == "" {
				pkg.Name = r.Module
			}
			pkg.Version = r.Version
			pkg.Ecosystem = r.Ecosystem
		case map[string]any:
			if name, ok := r["package"].(string); ok && name != "" {
				pkg.Name = name
			} else if name, ok := r["module"].(string); ok {
				pkg.Name = name
			}
			if version, ok := r["version"].(string); ok {
				pkg.Version = version
			}
			if ecosystem, ok := r["ecosystem"].(string); ok {
				pkg.Ecosystem = ecosystem
			}
			// Licenses may be in the request map
			if licenses, ok := r["licenses"].([]string); ok {
				pkg.Licenses = licenses
			} else if licenses, ok := r["licenses"].([]any); ok {
				for _, l := range licenses {
					if s, ok := l.(string); ok {
						pkg.Licenses = append(pkg.Licenses, s)
					}
				}
			}
		}
	}

	// Also check for licenses at input level (proxy adds them there too)
	if len(pkg.Licenses) == 0 {
		if licenses, ok := input["licenses"].([]string); ok {
			pkg.Licenses = licenses
		} else if licenses, ok := input["licenses"].([]any); ok {
			for _, l := range licenses {
				if s, ok := l.(string); ok {
					pkg.Licenses = append(pkg.Licenses, s)
				}
			}
		}
	}

	return pkg
}


// buildImageFromInput synthesizes an image map from image_info and target protos.
// The synthesized map provides fields like image.image, image.config, image.metadata,
// and image.history for CEL policy expressions.
func buildImageFromInput(input map[string]any) map[string]any {
	// Start with empty image structure
	image := map[string]any{}

	// Extract image reference from target proto
	if target := input["target"]; target != nil {
		if t, ok := target.(*targetv1.Target); ok {
			// Use Reference field for container images, otherwise DisplayPath
			ref := t.Reference
			if ref == "" {
				ref = t.DisplayPath
			}
			if ref != "" {
				image["image"] = ref
			}
			// Copy provenance fields (registry, repository, tag, digest)
			if t.Provenance != nil {
				for k, v := range t.Provenance {
					image[k] = v
				}
			}
		}
	}

	// Note: For OCI proxy contexts, image provenance (registry, repository, tag, digest)
	// should be set directly in the target.Provenance map by the caller.
	// The ProxyRequest proto is for package requests, not OCI image requests.

	// Handle image_info proto - check both "image_info" and "image" keys
	for _, key := range []string{"image_info", "image"} {
		if info := input[key]; info != nil {
			if imgInfo, ok := info.(*scanv1.ImageInfo); ok {
				if imgInfo.Config != nil {
					image["config"] = imgInfo.Config
				}
				if imgInfo.Metadata != nil {
					image["metadata"] = imgInfo.Metadata
				}
				if len(imgInfo.History) > 0 {
					image["history"] = imgInfo.History
				}
				break // Found ImageInfo, stop searching
			}
		}
	}

	// Compute reference field (digest takes precedence over tag)
	if digest, ok := image["digest"].(string); ok && digest != "" {
		image["reference"] = digest
	} else if tag, ok := image["tag"].(string); ok && tag != "" {
		image["reference"] = tag
	}

	// Compute composite image field if not already set (registry/repository:tag or @digest)
	if _, hasImage := image["image"]; !hasImage {
		if reg, ok := image["registry"].(string); ok {
			if repo, ok := image["repository"].(string); ok {
				composite := reg + "/" + repo
				if digest, ok := image["digest"].(string); ok && digest != "" {
					composite += "@" + digest
				} else if tag, ok := image["tag"].(string); ok && tag != "" {
					composite += ":" + tag
				}
				image["image"] = composite
			}
		}
	}

	return image
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

// compileSource compiles a raw policy source into a CEL program.
// It uses the default variable set declared in defaultVariableNames.
// Unknown variables will result in compilation errors - this is intentional
// to prevent injection of arbitrary variable names through policy content.
func compileSource(src Source) (celProgram, error) {
	env, err := envWithNames(nil)
	if err != nil {
		return nil, err
	}
	ast, iss := env.Compile(src.Body)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("%s: %w", src.Name, iss.Err())
	}
	prog, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src.Name, err)
	}
	return prog, nil
}

// deepCloneMap creates a deep copy of a map[string]any, recursively cloning
// nested maps and slices to prevent side effects from policy evaluation.
func deepCloneMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCloneValue(v)
	}
	return out
}

// deepCloneValue recursively clones a value, handling maps, slices, and primitives.
// Proto messages and other complex types are not cloned (they are typically immutable
// or should not be modified by policies).
func deepCloneValue(v any) any {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case map[string]any:
		return deepCloneMap(val)
	case []any:
		out := make([]any, len(val))
		for i, elem := range val {
			out[i] = deepCloneValue(elem)
		}
		return out
	case []string:
		out := make([]string, len(val))
		copy(out, val)
		return out
	case []int:
		out := make([]int, len(val))
		copy(out, val)
		return out
	case []int64:
		out := make([]int64, len(val))
		copy(out, val)
		return out
	case []float64:
		out := make([]float64, len(val))
		copy(out, val)
		return out
	default:
		// Primitives (string, int, bool, etc.) and proto messages are returned as-is.
		// Proto messages should be treated as immutable by policies.
		return v
	}
}
