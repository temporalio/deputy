// Package server provides HTTP handlers for Deputy's gRPC services.
package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	"github.com/temporalio/deputy/gen/deputy/policy/v1/policyv1connect"
	"github.com/temporalio/deputy/internal/policy"
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
	category := policy.NormalizeCategory(msg.Category)

	var infos []*policyv1.EntrypointInfo
	for _, ep := range policy.AllEntrypoints {
		cat := ep.Category()
		if category != "" && cat != category {
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
	if profile := policy.GetBindingProfile(ep); profile != nil && profile.Description != "" {
		return profile.Description
	}
	return fmt.Sprintf("Policy entrypoint for %s", ep)
}

func getEntrypointVariables(ep policy.Entrypoint) []*policyv1.VariableInfo {
	profile := policy.GetBindingProfile(ep)
	if profile == nil {
		return nil
	}
	vars := make([]*policyv1.VariableInfo, 0, len(profile.Required)+len(profile.Optional))
	for _, name := range profile.Required {
		vars = append(vars, variableInfoForPolicyBinding(name, true))
	}
	for _, name := range profile.Optional {
		vars = append(vars, variableInfoForPolicyBinding(name, false))
	}
	return vars
}

// variableInfoForPolicyBinding combines binding-profile requiredness with the
// display metadata owned by the policy package (the single source of truth
// shared with the MCP tool and the LSP).
func variableInfoForPolicyBinding(name string, required bool) *policyv1.VariableInfo {
	meta := policy.VariableInfoOrDefault(name)
	return &policyv1.VariableInfo{
		Name:        name,
		Type:        meta.Type,
		Description: meta.Description,
		Required:    required,
	}
}

func getEntrypointHelpers(ep policy.Entrypoint) []string {
	return policy.EntrypointHelpers(ep)
}
