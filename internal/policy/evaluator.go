package policy

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"google.golang.org/protobuf/proto"
)

var (
	anyType = reflect.TypeFor[any]()

	defaultVariableNames = []string{
		"pkg",
		"request",
		"target",
		"image",
		"image_info", // Container image config, metadata, and build history
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
		"top_packages", // Triage package summaries, most urgent first
		"base_ref",     // Diff base reference
		"target_ref",   // Diff target reference
		// Container diff specific variables
		"base_image",
		"target_image",
		"package_changes",
		"vulnerability_changes",
		"config_changes",
		"layer_analysis",
		"summary",
		"layer",
		// Dockerfile specific variables
		"dockerfile",
		"dockerfile_analysis",
		"stage",
		// Secrets specific variables
		"secret",
		"secrets",
		"report",
		// Graph specific variables
		"graph",       // Full graph data (stats, nodes, edges)
		"node",        // Current node in graph_node entrypoint
		"edge",        // Current edge in graph_edge entrypoint
		"from_node",   // Source node for edge
		"to_node",     // Target node for edge
		"nodes",       // All nodes in graph
		"edges",       // All edges in graph
		"stats",       // Graph statistics
		"roots",       // Root (direct) dependencies
		"ancestors",   // Ancestor nodes for current node
		"descendants", // Descendant nodes for current node
		// Constants for policy authoring
		// Sandbox execution variables, bound by Manager.evaluateExecutionPolicy.
		// Only the sandbox_execution entrypoint has an evaluation site today, so
		// only what it actually binds is declared here; see bindings_test.go for
		// the rest of the sandbox surface, which has no caller to bind it.
		"command",
		"workspace_dir",
		"requested_config",
		"context",

		"severity", // Severity constants: severity.critical, severity.high, etc.
		"scope",    // Dependency scope constants: scope.RUNTIME, scope.DEV, etc.
	}

	// severityConstants provides named severity levels for cleaner policy expressions.
	// These map to proto enum values for direct comparison with vulnerability.advisory.severity.level.
	// Instead of: vulnerability.advisory.severity.level == deputy.vulnerability.v1.SeverityLevel.SEVERITY_LEVEL_CRITICAL
	// Authors can write: vulnerability.advisory.severity.level == severity.critical
	severityConstants = map[string]any{
		"critical":    vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
		"high":        vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
		"medium":      vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM,
		"low":         vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW,
		"unspecified": vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_UNSPECIFIED,
	}

	// scopeConstants provides named dependency scopes for graph policies.
	// Instead of: edgeScope(edge) == "runtime"
	// Authors can write: edgeScope(edge) == scope.RUNTIME
	scopeConstants = map[string]any{
		"RUNTIME":     "runtime",
		"DEV":         "dev",
		"TEST":        "test",
		"BUILD":       "build",
		"OPTIONAL":    "optional",
		"UNSPECIFIED": "unspecified",
	}
)

// DefaultVariableNames returns the identifiers that Deputy injects into CEL
// environments for policies. Tooling (e.g., LSP) uses this to stay aligned with
// the runtime without duplicating the list.
func DefaultVariableNames() []string {
	return slices.Clone(defaultVariableNames)
}

// SeverityConstants returns the severity constants map for CEL expressions.
// This allows external packages to use the same constants (severity.critical, etc.)
func SeverityConstants() map[string]any {
	return severityConstants
}

// SeverityConstantNames returns the member names of the severity constants map
// (critical, high, medium, low, unspecified), ordered from most to least
// severe. Tooling (REPL, LSP completions) must derive severity member lists
// from this function so the names they teach can never drift from what the
// runtime actually binds.
func SeverityConstantNames() []string {
	names := make([]string, 0, len(severityConstants))
	for name := range severityConstants {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int {
		// Descending severity: critical first, unspecified last.
		return cmp.Compare(severityLevelNumber(b), severityLevelNumber(a))
	})
	return names
}

// severityLevelNumber returns the proto enum number backing a severity
// constant, used to order constant names by severity rank.
func severityLevelNumber(name string) int32 {
	level, ok := severityConstants[name].(vulnerabilityv1.SeverityLevel)
	if !ok {
		return -1
	}
	return int32(level)
}

// NewFilterEnv creates a CEL environment suitable for filter expressions.
// It includes the vulnerability variable and severity constants.
func NewFilterEnv() (*cel.Env, error) {
	return envWithNames([]string{"vulnerability", "severity"})
}

// Evaluate compiles the provided CEL source and evaluates it against the input
// document. Input keys are exposed to the CEL program as top-level identifiers.
// This is a low-level function for ad-hoc CEL evaluation; prefer Engine.EvaluateAll
// with typed PolicyInput protos for policy evaluation.
func Evaluate(ctx context.Context, source string, input map[string]any) (any, error) {
	// Clone input to avoid side effects on the caller's map.
	input = maps.Clone(input)
	if input == nil {
		input = map[string]any{}
	}
	// Convert any proto messages in the input map to native maps for CEL evaluation.
	// This allows tests to pass proto objects directly in the input map.
	input = convertProtosInMap(input)
	// Inject constants for cleaner policy authoring
	seedConstants(input)
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

// convertProtosInMap recursively converts any proto.Message values in the map to
// map[string]any for CEL evaluation. This enables tests to pass proto objects
// directly in input maps.
func convertProtosInMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = convertProtoValue(v)
	}
	return out
}

// convertProtoValue converts a value, recursively handling proto messages, maps, and slices.
func convertProtoValue(v any) any {
	if v == nil {
		return nil
	}
	// Check if it's a proto message
	if msg, ok := v.(proto.Message); ok {
		converted, err := ProtoToMap(msg)
		if err != nil {
			// If conversion fails, return the original value
			return v
		}
		return converted
	}
	// Handle maps
	if m, ok := v.(map[string]any); ok {
		return convertProtosInMap(m)
	}
	// Handle slices
	if s, ok := v.([]any); ok {
		out := make([]any, len(s))
		for i, elem := range s {
			out[i] = convertProtoValue(elem)
		}
		return out
	}
	return v
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

	// Pinned cel-go libraries come first so that they, and not an unpinned
	// registration of the same library, define the available functions. See
	// celextensions.go for the pinned versions and why they are pinned.
	opts := celExtensionOptions()
	opts = append(opts,
		// Register proto types for native proto support in CEL expressions.
		// This enables policies to work directly with proto messages, providing:
		// - Type-safe field access (e.g., finding.advisory.severity.level)
		// - Proto enum support (e.g., SeverityLevel_SEVERITY_LEVEL_HIGH)
		// - Proper nested message handling
		cel.Types(
			// Core domain types
			&vulnerabilityv1.Finding{},
			&vulnerabilityv1.Advisory{},
			&vulnerabilityv1.Severity{},
			&vulnerabilityv1.Stats{},
			&dependencyv1.Package{},
			&targetv1.Target{},
			// Common policy types
			&policyv1.Environment{},
			&policyv1.JWTClaims{},
			&policyv1.ProxyRequest{},
			&policyv1.ServiceRequest{},
			// Scan policy inputs
			&policyv1.ScanVulnerabilityPolicyInput{},
			&policyv1.ScanReportPolicyInput{},
			// Proxy policy inputs
			&policyv1.GoArtifactRequestPolicyInput{},
			&policyv1.NpmArtifactRequestPolicyInput{},
			&policyv1.PypiArtifactRequestPolicyInput{},
			&policyv1.RubygemsArtifactRequestPolicyInput{},
			&policyv1.OciArtifactRequestPolicyInput{},
			// SBOM policy inputs
			&policyv1.SbomReportPolicyInput{},
			&policyv1.SbomComponentPolicyInput{},
			// Diff policy inputs
			&policyv1.DiffReportPolicyInput{},
			&policyv1.DiffDependencyChangePolicyInput{},
			&policyv1.DiffVulnerabilityPolicyInput{},
			&policyv1.DependencyChange{},
			// Container diff policy inputs
			&policyv1.ContainerDiffReportPolicyInput{},
			&policyv1.ContainerDiffChangePolicyInput{},
			&policyv1.ContainerDiffVulnerabilityPolicyInput{},
			&policyv1.ContainerDiffLayerPolicyInput{},
			&policyv1.ContainerDiffConfigPolicyInput{},
			&policyv1.ContainerPackageChange{},
			&policyv1.ContainerVulnerabilityChange{},
			&policyv1.ContainerConfigDiff{},
			&policyv1.ContainerImageRef{},
			&policyv1.LayerChange{},
			// Secrets policy inputs
			&policyv1.SecretsReportPolicyInput{},
			&policyv1.SecretsFindingPolicyInput{},
			// Graph policy inputs
			&policyv1.GraphReportPolicyInput{},
			&policyv1.GraphNodePolicyInput{},
			&policyv1.GraphEdgePolicyInput{},
			&policyv1.GraphNode{},
			&policyv1.GraphEdge{},
			&policyv1.GraphStats{},
			// Fix policy inputs
			&policyv1.FixPlanPolicyInput{},
			&policyv1.FixPlanStepPolicyInput{},
			&policyv1.RemediationCommand{},
			// Triage policy inputs
			&policyv1.TriageReportPolicyInput{},
			&policyv1.TriageClusterPolicyInput{},
			&policyv1.TriagePackageSummary{},
			// Dockerfile policy inputs
			&policyv1.DockerfileReportPolicyInput{},
			&policyv1.DockerfileStagePolicyInput{},
			&policyv1.DockerfileInfo{},
			&policyv1.DockerfileStage{},
			&policyv1.DockerfileAnalysis{},
			&policyv1.ImageReference{},
			// Service policy inputs (server authorization)
			&policyv1.ServiceScanRequestPolicyInput{},
			&policyv1.ServiceListRequestPolicyInput{},
			&policyv1.ServiceSbomRequestPolicyInput{},
			&policyv1.ServiceDiffRequestPolicyInput{},
			&policyv1.ServiceSecretsRequestPolicyInput{},
			&policyv1.ServiceGraphRequestPolicyInput{},
			// Scan service types for container image policies
			&scanv1.ImageInfo{},
			&scanv1.ImageConfig{},
			&scanv1.ImageMetadata{},
			&scanv1.HistoryEntry{},
			&scanv1.Healthcheck{},
			// Container types (used by container diff and OCI policies)
			&containerv1.LayerDetails{},
			&containerv1.ImageInfo{},
			&containerv1.ImageConfig{},
			&containerv1.ImageMetadata{},
			&containerv1.HistoryEntry{},
			&containerv1.HealthcheckConfig{},
			// Secrets policy types (inline definitions to avoid circular imports)
			&policyv1.SecretFinding{},
			&policyv1.SecretStats{},
		),
	)
	// Register each input variable as a dynamically-typed CEL variable.
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" {
			opts = append(opts, cel.Variable(name, cel.DynType))
		}
	}
	opts = append(opts, customHelperFunctions()...)
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return nil, fmt.Errorf("build CEL env: %w", err)
	}
	return env, nil
}

// convertRefVal converts a CEL ref.Val to a native Go value.
// The path parameter tracks the location in nested structures for error context.
func convertRefVal(val ref.Val) (any, error) {
	return convertRefValWithPath(val, "")
}

// convertRefValWithPath converts a CEL ref.Val with path tracking for better error messages.
func convertRefValWithPath(val ref.Val, path string) (any, error) {
	if val == nil {
		return nil, nil
	}
	switch v := val.Value().(type) {
	case []ref.Val:
		out := make([]any, len(v))
		for i, elem := range v {
			elemPath := fmt.Sprintf("%s[%d]", path, i)
			if path == "" {
				elemPath = fmt.Sprintf("[%d]", i)
			}
			converted, err := convertRefValWithPath(elem, elemPath)
			if err != nil {
				return nil, err
			}
			out[i] = converted
		}
		return out, nil
	case map[ref.Val]ref.Val:
		out := make(map[string]any, len(v))
		for mk, mv := range v {
			keyVal, err := convertRefValWithPath(mk, path+".key")
			if err != nil {
				return nil, fmt.Errorf("at %s: %w", path, err)
			}
			keyStr, ok := keyVal.(string)
			if !ok {
				location := path
				if location == "" {
					location = "root"
				}
				return nil, fmt.Errorf("at %s: map keys must be strings, got %T", location, keyVal)
			}
			valPath := path + "." + keyStr
			if path == "" {
				valPath = keyStr
			}
			valVal, err := convertRefValWithPath(mv, valPath)
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
		location := path
		if location == "" {
			location = "root"
		}
		return nil, fmt.Errorf("at %s: unable to convert CEL value of type %T", location, val.Value())
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
			curr[i] = min(del, ins, sub)
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
