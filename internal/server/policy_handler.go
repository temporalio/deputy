// Package server provides HTTP handlers for Deputy's gRPC services.
package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	policyv1 "github.com/picatz/deputy/gen/deputy/policy/v1"
	"github.com/picatz/deputy/gen/deputy/policy/v1/policyv1connect"
	"github.com/picatz/deputy/internal/policy"
	"google.golang.org/protobuf/proto"
)

// PolicyHandler implements the PolicyService.
type PolicyHandler struct {
	policyv1connect.UnimplementedPolicyServiceHandler
	localMode bool
}

// PolicyOption configures the policy handler.
type PolicyOption func(*PolicyHandler)

// WithPolicyLocalMode enables local filesystem access for policy files.
func WithPolicyLocalMode() PolicyOption {
	return func(h *PolicyHandler) {
		h.localMode = true
	}
}

// NewPolicyHandler creates a new PolicyServiceHandler.
func NewPolicyHandler(opts ...PolicyOption) *PolicyHandler {
	h := &PolicyHandler{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Ensure PolicyHandler implements the interface.
var _ policyv1connect.PolicyServiceHandler = (*PolicyHandler)(nil)

// Evaluate runs policy evaluation against provided context.
func (h *PolicyHandler) Evaluate(
	ctx context.Context,
	req *connect.Request[policyv1.EvaluateRequest],
) (*connect.Response[policyv1.EvaluateResponse], error) {
	msg := req.Msg

	// Load policies from sources
	sources, policyErrors := h.loadPolicySources(msg.Policies)
	if len(policyErrors) > 0 && len(sources) == 0 {
		return connect.NewResponse(&policyv1.EvaluateResponse{
			Outcome: policyv1.ActionType_ACTION_TYPE_UNSPECIFIED,
			Errors:  policyErrors,
		}), nil
	}

	// Build CEL activation based on context type
	input, entrypoint, command, err := h.buildActivation(msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// Create engine and evaluate
	engine, err := policy.NewEngine(sources)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("compile policies: %w", err))
	}

	actions, err := engine.EvaluateAll(ctx, input, command, entrypoint)
	if err != nil {
		policyErrors = append(policyErrors, &policyv1.PolicyError{
			Message: fmt.Sprintf("evaluation error: %v", err),
		})
	}

	// Convert actions to proto
	protoActions := make([]*policyv1.Action, 0, len(actions))
	for _, a := range actions {
		protoActions = append(protoActions, &policyv1.Action{
			Type:        actionTypeToProto(a.Type),
			PolicyName:  a.Source,
			Reason:      a.Reason,
			Remediation: a.Remediation,
			Entrypoint:  entrypoint,
		})
	}

	// Determine overall outcome
	outcome := policyv1.ActionType_ACTION_TYPE_ALLOW
	for _, a := range protoActions {
		if a.Type == policyv1.ActionType_ACTION_TYPE_DENY {
			outcome = policyv1.ActionType_ACTION_TYPE_DENY
			break
		}
		if a.Type == policyv1.ActionType_ACTION_TYPE_WARN {
			outcome = policyv1.ActionType_ACTION_TYPE_WARN
		}
	}

	return connect.NewResponse(&policyv1.EvaluateResponse{
		Actions: protoActions,
		Outcome: outcome,
		Errors:  policyErrors,
	}), nil
}

// Validate checks policy syntax and CEL expressions.
func (h *PolicyHandler) Validate(
	ctx context.Context,
	req *connect.Request[policyv1.ValidateRequest],
) (*connect.Response[policyv1.ValidateResponse], error) {
	msg := req.Msg

	sources, parseErrors := h.loadPolicySources(msg.Policies)

	var allErrors []*policyv1.PolicyError
	var allWarnings []*policyv1.PolicyError
	var summaries []*policyv1.PolicySummary

	allErrors = append(allErrors, parseErrors...)

	for _, src := range sources {
		// Try to compile the source to validate CEL syntax
		if err := policy.Compile(src.Body, nil); err != nil {
			allErrors = append(allErrors, &policyv1.PolicyError{
				PolicyName: src.Name,
				Message:    fmt.Sprintf("CEL compilation error: %v", err),
			})
			continue
		}

		// Extract metadata from the source for summary
		meta := extractMetadataFromSource(src.Body)
		summaries = append(summaries, &policyv1.PolicySummary{
			Name:        meta.name,
			Description: meta.description,
			Entrypoints: meta.entrypoints,
			RuleCount:   int32(meta.ruleCount),
			Variables:   meta.variables,
		})
	}

	return connect.NewResponse(&policyv1.ValidateResponse{
		Valid:     len(allErrors) == 0,
		Errors:    allErrors,
		Warnings:  allWarnings,
		Summaries: summaries,
	}), nil
}

// ListEntrypoints returns all available policy entrypoints.
func (h *PolicyHandler) ListEntrypoints(
	ctx context.Context,
	req *connect.Request[policyv1.ListEntrypointsRequest],
) (*connect.Response[policyv1.ListEntrypointsResponse], error) {
	msg := req.Msg

	var infos []*policyv1.EntrypointInfo
	for _, ep := range policy.AllEntrypoints {
		cat := ep.Category()
		if msg.Category != "" && cat != msg.Category {
			continue
		}

		info := &policyv1.EntrypointInfo{
			Name:        string(ep),
			Category:    cat,
			Description: getEntrypointDescription(ep),
			Variables:   getEntrypointVariables(ep),
			Helpers:     getEntrypointHelpers(ep),
		}
		infos = append(infos, info)
	}

	return connect.NewResponse(&policyv1.ListEntrypointsResponse{
		Entrypoints: infos,
	}), nil
}

// loadPolicySources loads policy content from the specified sources and parses them.
func (h *PolicyHandler) loadPolicySources(protoSources []*policyv1.PolicySource) ([]policy.Source, []*policyv1.PolicyError) {
	var sources []policy.Source
	var errors []*policyv1.PolicyError

	for _, src := range protoSources {
		switch s := src.Source.(type) {
		case *policyv1.PolicySource_Inline:
			// Parse inline YAML content
			parsed, err := policy.ParseStructuredSources([]byte(s.Inline), "inline")
			if err != nil {
				errors = append(errors, &policyv1.PolicyError{
					Message: fmt.Sprintf("parse inline policy: %v", err),
				})
				continue
			}
			sources = append(sources, parsed...)

		case *policyv1.PolicySource_Path:
			if !h.localMode {
				errors = append(errors, &policyv1.PolicyError{
					Message: "file path sources require local mode; use inline policies or enable local mode",
				})
				continue
			}
			// Load from filesystem using LoadSources
			loaded, err := policy.LoadSources([]string{s.Path})
			if err != nil {
				errors = append(errors, &policyv1.PolicyError{
					Message: fmt.Sprintf("load policy file %s: %v", s.Path, err),
				})
				continue
			}
			sources = append(sources, loaded...)

		case *policyv1.PolicySource_Url:
			errors = append(errors, &policyv1.PolicyError{
				Message: "URL policy sources not yet implemented",
			})
			continue

		default:
			errors = append(errors, &policyv1.PolicyError{
				Message: "unknown policy source type",
			})
		}
	}

	return sources, errors
}

// buildActivation constructs the policy input proto from request input.
// Returns the typed proto, entrypoint, and command.
func (h *PolicyHandler) buildActivation(msg *policyv1.EvaluateRequest) (proto.Message, string, string, error) {
	switch input := msg.Input.(type) {
	case *policyv1.EvaluateRequest_ScanVulnerability:
		return input.ScanVulnerability,
			string(policy.EntrypointScanVulnerability),
			commandFromEnv(input.ScanVulnerability.Env), nil

	case *policyv1.EvaluateRequest_ScanReport:
		return input.ScanReport,
			string(policy.EntrypointScanReport),
			commandFromEnv(input.ScanReport.Env), nil

	case *policyv1.EvaluateRequest_GoArtifactRequest:
		return input.GoArtifactRequest,
			string(policy.EntrypointGoArtifactRequest),
			commandFromEnv(input.GoArtifactRequest.Env), nil

	case *policyv1.EvaluateRequest_NpmArtifactRequest:
		return input.NpmArtifactRequest,
			string(policy.EntrypointNpmArtifactRequest),
			commandFromEnv(input.NpmArtifactRequest.Env), nil

	case *policyv1.EvaluateRequest_PypiArtifactRequest:
		return input.PypiArtifactRequest,
			string(policy.EntrypointPypiArtifactRequest),
			commandFromEnv(input.PypiArtifactRequest.Env), nil

	case *policyv1.EvaluateRequest_OciArtifactRequest:
		return input.OciArtifactRequest,
			string(policy.EntrypointOCIArtifactRequest),
			commandFromEnv(input.OciArtifactRequest.Env), nil

	default:
		return nil, "", "", fmt.Errorf("no evaluation input provided")
	}
}

// commandFromEnv extracts the command from the environment proto.
func commandFromEnv(env *policyv1.Environment) string {
	if env == nil {
		return ""
	}
	return env.Command
}

// Helper functions

func actionTypeToProto(action string) policyv1.ActionType {
	switch action {
	case "allow":
		return policyv1.ActionType_ACTION_TYPE_ALLOW
	case "deny":
		return policyv1.ActionType_ACTION_TYPE_DENY
	case "warn":
		return policyv1.ActionType_ACTION_TYPE_WARN
	default:
		return policyv1.ActionType_ACTION_TYPE_UNSPECIFIED
	}
}

// policyMeta holds extracted metadata from a policy source.
type policyMeta struct {
	name        string
	description string
	entrypoints []string
	ruleCount   int
	variables   []string
}

// extractMetadataFromSource parses metadata from a CEL source body.
// It looks for //! comments at the beginning of the source.
func extractMetadataFromSource(body string) policyMeta {
	meta := policyMeta{}

	// Try to parse as structured bundle first to get rich metadata
	bundle, ok, _ := policy.TryParseStructuredBundleBytes([]byte(body))
	if ok && len(bundle.Policies) > 0 {
		p := bundle.Policies[0]
		meta.name = p.Name
		meta.description = p.Description
		meta.entrypoints = p.Entrypoints
		meta.ruleCount = len(p.Rules)
		meta.variables = p.Vars.Names()
		return meta
	}

	// Fall back to parsing //! comments from raw CEL
	// This is a simplified version - the actual parsing happens in policy.parsePolicyMetadata
	// but that's internal. We'll just count rules by looking for action patterns.
	meta.ruleCount = 1 // Default to 1 if we can't determine
	return meta
}

func getEntrypointDescription(ep policy.Entrypoint) string {
	descriptions := map[policy.Entrypoint]string{
		policy.EntrypointScanReport:              "Evaluated after a vulnerability scan completes with the full report",
		policy.EntrypointScanVulnerability:       "Evaluated for each vulnerability found during a scan",
		policy.EntrypointGoArtifactRequest:       "Evaluated when the proxy handles a Go module request",
		policy.EntrypointNpmArtifactRequest:      "Evaluated when the proxy handles an npm package request",
		policy.EntrypointPypiArtifactRequest:     "Evaluated when the proxy handles a PyPI package request",
		policy.EntrypointRubygemsArtifactRequest: "Evaluated when the proxy handles a RubyGems package request",
		policy.EntrypointOCIArtifactRequest:      "Evaluated when the proxy handles an OCI artifact request",
		policy.EntrypointGraphReport:             "Evaluated after dependency graph resolution",
		policy.EntrypointGraphNode:               "Evaluated for each node in the dependency graph",
		policy.EntrypointGraphEdge:               "Evaluated for each edge in the dependency graph",
		policy.EntrypointDockerfileReport:        "Evaluated after Dockerfile analysis",
		policy.EntrypointDockerfileStage:         "Evaluated for each stage in a Dockerfile",
		policy.EntrypointSecretsReport:           "Evaluated after secrets scanning",
		policy.EntrypointSecretsFinding:          "Evaluated for each secret found",
		policy.EntrypointSBOMComponent:           "Evaluated for each component in an SBOM",
		policy.EntrypointDiffDependencyChange:    "Evaluated for each dependency change in a diff",
	}
	if desc, ok := descriptions[ep]; ok {
		return desc
	}
	return fmt.Sprintf("Policy entrypoint for %s", ep)
}

func getEntrypointVariables(ep policy.Entrypoint) []*policyv1.VariableInfo {
	switch ep {
	case policy.EntrypointScanVulnerability:
		return []*policyv1.VariableInfo{
			{Name: "vulnerability", Type: "vulnerabilityv1.Finding", Description: "The vulnerability being evaluated"},
			{Name: "pkg", Type: "dependencyv1.Package", Description: "The affected package"},
			{Name: "env", Type: "policyv1.Environment", Description: "Execution environment context"},
			{Name: "target", Type: "targetv1.Target", Description: "What was scanned"},
		}
	case policy.EntrypointScanReport:
		return []*policyv1.VariableInfo{
			{Name: "vulnerabilities", Type: "list(vulnerabilityv1.Finding)", Description: "All vulnerabilities found"},
			{Name: "packages", Type: "list(dependencyv1.Package)", Description: "All packages scanned"},
			{Name: "stats", Type: "vulnerabilityv1.Stats", Description: "Vulnerability counts by severity"},
			{Name: "env", Type: "policyv1.Environment", Description: "Execution environment context"},
			{Name: "target", Type: "targetv1.Target", Description: "What was scanned"},
		}
	case policy.EntrypointGraphReport:
		return []*policyv1.VariableInfo{
			{Name: "nodes", Type: "list(graphv1.Node)", Description: "All dependency graph nodes"},
			{Name: "edges", Type: "list(graphv1.Edge)", Description: "All dependency relationships"},
			{Name: "stats", Type: "graphv1.GraphStats", Description: "Graph statistics"},
			{Name: "roots", Type: "list(string)", Description: "Direct dependency PURLs"},
		}
	case policy.EntrypointGraphNode:
		return []*policyv1.VariableInfo{
			{Name: "node", Type: "graphv1.Node", Description: "The current graph node"},
			{Name: "ancestors", Type: "list(graphv1.Node)", Description: "Ancestor nodes"},
			{Name: "descendants", Type: "list(graphv1.Node)", Description: "Descendant nodes"},
		}
	case policy.EntrypointGraphEdge:
		return []*policyv1.VariableInfo{
			{Name: "edge", Type: "graphv1.Edge", Description: "The current graph edge"},
			{Name: "from_node", Type: "graphv1.Node", Description: "Source node of the edge"},
			{Name: "to_node", Type: "graphv1.Node", Description: "Target node of the edge"},
		}
	case policy.EntrypointGoArtifactRequest, policy.EntrypointNpmArtifactRequest,
		policy.EntrypointPypiArtifactRequest, policy.EntrypointRubygemsArtifactRequest:
		return []*policyv1.VariableInfo{
			{Name: "request", Type: "policyv1.ProxyRequest", Description: "The package request being evaluated"},
			{Name: "jwt", Type: "policyv1.JWTClaims", Description: "JWT claims from authenticated requests"},
			{Name: "vulnerabilities", Type: "list(vulnerabilityv1.Finding)", Description: "Known vulnerabilities for the package"},
			{Name: "env", Type: "policyv1.Environment", Description: "Execution environment context"},
		}
	case policy.EntrypointOCIArtifactRequest:
		return []*policyv1.VariableInfo{
			{Name: "request", Type: "policyv1.ProxyRequest", Description: "The OCI artifact request"},
			{Name: "image", Type: "map", Description: "Container image metadata"},
			{Name: "jwt", Type: "policyv1.JWTClaims", Description: "JWT claims from authenticated requests"},
			{Name: "vulnerabilities", Type: "list(vulnerabilityv1.Finding)", Description: "Known vulnerabilities"},
		}
	case policy.EntrypointDockerfileReport:
		return []*policyv1.VariableInfo{
			{Name: "dockerfile", Type: "map", Description: "Parsed Dockerfile structure"},
			{Name: "dockerfile_analysis", Type: "map", Description: "Dockerfile analysis results"},
		}
	case policy.EntrypointDockerfileStage:
		return []*policyv1.VariableInfo{
			{Name: "stage", Type: "map", Description: "Current Dockerfile stage"},
			{Name: "dockerfile", Type: "map", Description: "Full Dockerfile structure"},
		}
	case policy.EntrypointSecretsReport:
		return []*policyv1.VariableInfo{
			{Name: "secrets", Type: "list(map)", Description: "All secrets found"},
			{Name: "report", Type: "map", Description: "Secrets scan report"},
		}
	case policy.EntrypointSecretsFinding:
		return []*policyv1.VariableInfo{
			{Name: "secret", Type: "map", Description: "The current secret finding"},
		}
	default:
		return nil
	}
}

func getEntrypointHelpers(ep policy.Entrypoint) []string {
	// Common helpers available at all entrypoints
	common := []string{"now()", "age()", "levenshtein()", "levenshteinWithin()"}

	switch ep.Category() {
	case "scan":
		return append(common, "ssvc()", "hasFix()", "inKEV()", "epssScore()")
	case "graph":
		return append(common, "graphMatch()", "isDirectDep()", "nodeDepth()", "nodeEcosystem()",
			"hasVulnerabilities()", "vulnerabilityCount()", "pathLength()", "pathContains()")
	case "proxy":
		return append(common, "imageRef()", "baseImage()")
	case "dockerfile":
		return common
	case "secrets":
		return common
	default:
		return common
	}
}
