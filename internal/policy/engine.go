package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"strconv"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/temporalio/deputy/internal/collections"
	"github.com/temporalio/deputy/internal/otel"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Evaluator is the interface for evaluating policies against a payload.
// It abstracts the policy engine for consumers that only need evaluation capability.
type Evaluator interface {
	Evaluate(ctx context.Context, entrypoint string, input proto.Message) ([]Action, error)
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
	mode        string                  // mode is the canonical execution mode (see Modes), or empty for the enforce default.
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
		mode, err := declaredMode(meta.Mode, src.Name)
		if err != nil {
			return nil, err
		}

		compiled = append(compiled, compiledPolicy{
			source:      src,
			program:     prog,
			entrypoints: collections.NewSetFunc(meta.Entrypoints, strings.TrimSpace),
			commands:    collections.NewSetFunc(meta.Commands, NormalizeCommand),
			mode:        mode,
		})
	}
	return &Engine{compiled: compiled}, nil
}

// declaredMode returns the canonical form of the mode a policy source declares,
// refusing one Deputy does not recognize. Evaluation asks whether a policy's mode
// is advisory and enforces when it is not, so an unrecognized spelling would turn
// a policy the author meant to observe with into one that blocks, which is both
// the opposite of what they asked for and silent. It is the load-time counterpart
// of validateEntrypoints, and of the check the structured bundle format runs while
// expanding a policy, so a mode is refused the same way whether it arrives as a
// bundle field or as a comment on a raw CEL source.
//
// Canonicalizing here is what lets every reader of the mode compare it without
// repeating the normalization: an authored " ADVISORY " is stored as advisory. An
// empty mode is absent rather than unknown and means enforce, the default, so it
// loads.
func declaredMode(mode, policyName string) (string, error) {
	if NormalizeMode(mode) == "" {
		return "", nil
	}
	canonical, err := ValidateMode(mode)
	if err != nil {
		return "", fmt.Errorf("%s: %w", policyName, err)
	}
	return canonical, nil
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

// EvaluateAll runs all compiled policies against the input proto and returns aggregated actions.
//
// The input should be a typed PolicyInput proto message (e.g., *policyv1.ScanVulnerabilityPolicyInput).
// The proto is converted to a map[string]any for CEL evaluation using protojson serialization,
// which preserves snake_case field names as defined in the proto schema.
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
func (e *Engine) EvaluateAll(ctx context.Context, input proto.Message, command, entrypoint string) ([]Action, error) {
	startTime := time.Now()
	if e == nil || len(e.compiled) == 0 {
		return nil, nil
	}
	command = NormalizeCommand(command)

	// Validate entrypoint at evaluation time if provided
	if entrypoint != "" && !IsAllowedEntrypoint(entrypoint) {
		return nil, fmt.Errorf("invalid entrypoint: %q", entrypoint)
	}

	// Convert proto to map[string]any for CEL evaluation.
	// This is the single conversion point - callers pass typed protos,
	// and CEL evaluates against the resulting map with snake_case keys.
	payload, err := ProtoToMap(input)
	if err != nil {
		return nil, fmt.Errorf("convert input to map: %w", err)
	}

	// Flatten JWT custom claims to allow jwt.roles instead of jwt.custom_claims.roles
	flattenJWTCustomClaims(payload)

	// Inject constants for cleaner policy authoring
	seedConstants(payload)

	// Ensure env.command and env.entrypoint are set
	if command != "" || entrypoint != "" {
		env, _ := payload["env"].(map[string]any)
		if env == nil {
			env = map[string]any{}
		}
		if command != "" {
			env["command"] = command
		}
		if entrypoint != "" {
			env["entrypoint"] = entrypoint
		}
		payload["env"] = env
	}

	span := otel.SpanFromContext(ctx)
	var actions []Action
	for _, pol := range e.compiled {
		if shouldSkip(pol, command, entrypoint) {
			continue
		}
		out, _, err := pol.program.ContextEval(ctx, payload)
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
		if strings.EqualFold(pol.mode, ModeAdvisory) {
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
// the input proto using the provided entrypoint, with command inferred from the
// input's env.command field (if present).
func (e *Engine) Evaluate(ctx context.Context, entrypoint string, input proto.Message) ([]Action, error) {
	// Try to extract command from input if it has an env field
	command := ""
	if payload, err := ProtoToMap(input); err == nil {
		if env, ok := payload["env"].(map[string]any); ok {
			if cmd, ok := env["command"].(string); ok {
				command = cmd
			}
		}
	}
	return e.EvaluateAll(ctx, input, command, entrypoint)
}

// EvaluateAllMap runs all compiled policies against a raw map[string]any input.
// This is for CLI testing scenarios where the input is arbitrary JSON rather than
// a typed proto. For production use, prefer EvaluateAll with typed proto inputs.
func (e *Engine) EvaluateAllMap(ctx context.Context, payload map[string]any, command, entrypoint string) ([]Action, error) {
	startTime := time.Now()
	if e == nil || len(e.compiled) == 0 {
		return nil, nil
	}
	command = NormalizeCommand(command)

	// Validate entrypoint at evaluation time if provided
	if entrypoint != "" && !IsAllowedEntrypoint(entrypoint) {
		return nil, fmt.Errorf("invalid entrypoint: %q", entrypoint)
	}

	// Clone the payload to avoid mutating caller's map
	payload = cloneMap(payload)

	// Convert any proto messages in the payload to native maps for CEL evaluation.
	// This allows callers to pass proto objects directly in the input map.
	payload = convertProtosInMap(payload)

	// Inject constants for cleaner policy authoring
	seedConstants(payload)

	// Ensure env.command and env.entrypoint are set
	if command != "" || entrypoint != "" {
		env, _ := payload["env"].(map[string]any)
		if env == nil {
			env = map[string]any{}
		}
		if command != "" {
			env["command"] = command
		}
		if entrypoint != "" {
			env["entrypoint"] = entrypoint
		}
		payload["env"] = env
	}

	span := otel.SpanFromContext(ctx)
	var actions []Action
	for _, pol := range e.compiled {
		if shouldSkip(pol, command, entrypoint) {
			continue
		}
		out, _, err := pol.program.ContextEval(ctx, payload)
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
		if strings.EqualFold(pol.mode, ModeAdvisory) {
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

// cloneMap creates a shallow copy of a map[string]any.
// This prevents mutation of the caller's map when we inject constants and env.
func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(m))
	maps.Copy(out, m)
	return out
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
	command = NormalizeCommand(command)

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

// seedConstants injects constant objects for cleaner policy authoring.
// These provide named values like severity.critical and scope.RUNTIME.
func seedConstants(payload map[string]any) {
	if payload == nil {
		return
	}
	payload["severity"] = severityConstants
	payload["scope"] = scopeConstants
}

// ProtoToMap converts a proto message to map[string]any for CEL evaluation.
// Uses protojson with UseProtoNames to preserve snake_case field names,
// UseEnumNumbers so enums serialize as integers for CEL comparison,
// and EmitUnpopulated to ensure empty arrays and zero values are present
// (required for policies that check size() on potentially empty lists).
// Returns an error if serialization fails; use protoToMap for internal use
// where errors can be safely ignored (e.g., example generation).
func ProtoToMap(msg proto.Message) (map[string]any, error) {
	if msg == nil {
		return map[string]any{}, nil
	}
	opts := protojson.MarshalOptions{
		UseProtoNames:   true, // Keep snake_case field names
		EmitUnpopulated: true, // Emit zero values so policies can check size() on empty lists
		UseEnumNumbers:  true, // Enums as integers for CEL
	}
	data, err := opts.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal proto: %w", err)
	}
	// Use a decoder with UseNumber to preserve numeric precision for int64 fields
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	var result map[string]any
	if err := dec.Decode(&result); err != nil {
		return nil, fmt.Errorf("unmarshal json: %w", err)
	}
	// Convert json.Number to proper numeric types for CEL
	convertJSONNumbers(result)
	// Remove null values so has() checks work correctly.
	// EmitUnpopulated emits nil message fields as null, but CEL's has() returns
	// true for keys that exist with null values, causing subsequent field access
	// to fail. By removing nulls, has() correctly returns false for absent fields.
	removeNullValues(result)
	return result, nil
}

// convertJSONNumbers recursively converts json.Number and numeric strings to
// int64 or float64 for proper CEL numeric comparison. Protojson serializes
// int64 as quoted strings to avoid JavaScript precision issues, but CEL needs
// proper numeric types.
func convertJSONNumbers(v any) {
	switch val := v.(type) {
	case map[string]any:
		for k, elem := range val {
			val[k] = convertNumericValue(elem)
			convertJSONNumbers(val[k])
		}
	case []any:
		for i, elem := range val {
			val[i] = convertNumericValue(elem)
			convertJSONNumbers(val[i])
		}
	}
}

// convertNumericValue converts json.Number or numeric strings to native Go numbers.
func convertNumericValue(elem any) any {
	switch v := elem.(type) {
	case json.Number:
		// Try int64 first, fall back to float64
		if i, err := v.Int64(); err == nil {
			return i
		}
		if f, err := v.Float64(); err == nil {
			return f
		}
	case string:
		// Protojson serializes int64/uint64 as quoted strings.
		// Try to parse as int64 first (handles most cases), then float64.
		if len(v) > 0 && (v[0] == '-' || (v[0] >= '0' && v[0] <= '9')) {
			// Looks like it might be a number, try parsing
			if i, err := strconv.ParseInt(v, 10, 64); err == nil {
				return i
			}
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f
			}
		}
	}
	return elem
}

// removeNullValues recursively removes null values from maps.
// This is needed because protojson with EmitUnpopulated emits nil message fields
// as null, but CEL's has() macro returns true for keys with null values.
// Removing nulls allows has() to work correctly for checking field presence.
func removeNullValues(v any) {
	switch val := v.(type) {
	case map[string]any:
		for k, elem := range val {
			if elem == nil {
				delete(val, k)
			} else {
				removeNullValues(elem)
			}
		}
	case []any:
		for _, elem := range val {
			removeNullValues(elem)
		}
	}
}

// flattenJWTCustomClaims promotes custom_claims fields to the jwt object level.
// This allows policies to use jwt.roles instead of jwt.custom_claims.roles,
// matching the documented API in AGENTS.md.
//
// The function handles two formats for array-like claims:
// - Comma-separated strings: "admin,scanner" -> ["admin", "scanner"]
// - Go string representation: "[admin scanner]" -> ["admin", "scanner"]
func flattenJWTCustomClaims(payload map[string]any) {
	jwt, ok := payload["jwt"].(map[string]any)
	if !ok {
		return
	}
	customClaims, ok := jwt["custom_claims"].(map[string]any)
	if !ok {
		return
	}
	// Promote each custom claim to the jwt level
	for k, v := range customClaims {
		// Skip if the key already exists at the jwt level (standard claims take precedence)
		if _, exists := jwt[k]; exists {
			continue
		}
		// Convert string values that look like arrays
		if strVal, ok := v.(string); ok {
			jwt[k] = parseClaimValue(strVal)
		} else {
			jwt[k] = v
		}
	}
}

// parseClaimValue converts string claim values to appropriate types.
// Array-like strings become []any, others remain as strings.
func parseClaimValue(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	// Handle Go slice string format: [value1 value2]
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		inner := strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
		inner = strings.TrimSpace(inner)
		if inner == "" {
			return []any{}
		}
		parts := strings.Fields(inner)
		result := make([]any, len(parts))
		for i, p := range parts {
			result[i] = p
		}
		return result
	}
	// Handle comma-separated format: value1,value2
	if strings.Contains(s, ",") {
		parts := strings.Split(s, ",")
		result := make([]any, len(parts))
		for i, p := range parts {
			result[i] = strings.TrimSpace(p)
		}
		return result
	}
	// Single value - keep as string
	return s
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
