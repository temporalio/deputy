// Package server provides HTTP handlers for Deputy's gRPC services.
package server

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	"github.com/temporalio/deputy/gen/deputy/policy/v1/policyv1connect"
	"github.com/temporalio/deputy/internal/policy"
	internalproto "github.com/temporalio/deputy/internal/proto"
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
//
// Evaluate fails closed. Any failure to load, compile, or evaluate a policy is
// returned as an error rather than as a decision, so a caller reading the
// outcome field can never read a failure as a permission: a policy that did
// not run cannot have allowed anything. This matches every other policy path
// (the service interceptor answers CodeInternal, the proxy answers 500, the
// CLI errors out). Callers that want per-policy problems reported as data,
// without evaluating, should use Validate.
func (h *PolicyHandler) Evaluate(
	ctx context.Context,
	req *connect.Request[policyv1.EvaluateRequest],
) (*connect.Response[policyv1.EvaluateResponse], error) {
	msg := req.Msg

	// Load policies from sources. A source that failed to load is a policy that
	// will not run, so evaluating the remainder would answer with a decision
	// that silently omits it. Refuse instead, matching how the other handlers
	// report caller-supplied source problems (CodeInvalidArgument), including
	// the local-mode refusal for path sources.
	sources, policyErrors := h.loadPolicySources(msg.Policies)
	if len(policyErrors) > 0 {
		return nil, policyConnectError(ctx, connect.CodeInvalidArgument, policySourceLoadError(policyErrors))
	}

	// Build CEL activation based on context type
	input, entrypoint, command, err := h.buildActivation(msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// Create engine and evaluate
	engine, err := policy.NewEngine(sources)
	if err != nil {
		return nil, policyConnectError(ctx, connect.CodeInvalidArgument, fmt.Errorf("compile policies: %w", err))
	}

	// An evaluation failure leaves the decision unknown, and unknown is not
	// allowed. The engine stops at the first failing policy and returns no
	// actions, so there is no partial result to hand back here either.
	actions, err := engine.EvaluateAll(ctx, input, command, entrypoint)
	if err != nil {
		return nil, policyConnectError(ctx, connect.CodeInternal,
			fmt.Errorf("evaluate policies for entrypoint %q: %w", entrypoint, err))
	}

	// Convert actions to proto through the shared converter so this surface
	// cannot drift from the CLI and MCP ones: it splits the engine's combined
	// "path::rule" source and carries message and code.
	protoActions := make([]*policyv1.Action, 0, len(actions))
	for _, a := range actions {
		protoActions = append(protoActions, internalproto.PolicyActionToProto(a, entrypoint, nil))
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

	// Reaching this point means every policy loaded, compiled, and ran, so the
	// outcome is a real decision. Anything else already returned an error
	// above, which is why EvaluateResponse carries no error list to fill in.
	return connect.NewResponse(&policyv1.EvaluateResponse{
		Actions: protoActions,
		Outcome: outcome,
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

		// Summarize from the metadata the loader parsed, which travels with the
		// source as typed data. Rule and variable counts are properties of the
		// expanded CEL program rather than the policy's declared metadata, so
		// the summary reports the program as a single rule.
		summaries = append(summaries, &policyv1.PolicySummary{
			Name:        src.Metadata.Name,
			Description: src.Metadata.Description,
			Entrypoints: src.Metadata.EntrypointNames(),
			RuleCount:   1,
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

// policyConnectError classifies a policy failure for the wire, giving context
// cancellation and deadline expiry precedence over the supplied fallback code.
//
// Connect cannot do this for us once we have already wrapped: its
// wrapIfContextError returns early when the error is a *connect.Error, so a
// canceled request wrapped in CodeInternal reaches the caller as a server
// failure it may retry rather than the cancellation it was. The precedence
// here mirrors connect's own wrapIfContextDone: consult the error chain first,
// then fall back to the context state, because a failure raised while the
// context is done is caused by the context whether or not the underlying
// library bothered to say so.
func policyConnectError(ctx context.Context, fallback connect.Code, err error) *connect.Error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(ctx.Err(), context.Canceled):
		return connect.NewError(connect.CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(ctx.Err(), context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, err)
	default:
		return connect.NewError(fallback, err)
	}
}

// policySourceLoadError collapses source load failures into one error so
// Evaluate can fail closed on them. Every message is kept, and the policy name
// where the loader knew one, because the caller no longer receives the response
// errors field once the RPC answers with an error instead of a decision: this
// error text is all it has to debug with.
func policySourceLoadError(policyErrors []*policyv1.PolicyError) error {
	causes := make([]error, 0, len(policyErrors))
	for _, pe := range policyErrors {
		msg := pe.GetMessage()
		if name := pe.GetPolicyName(); name != "" {
			causes = append(causes, fmt.Errorf("%s: %s", name, msg))
			continue
		}
		causes = append(causes, errors.New(msg))
	}
	return fmt.Errorf("load policy sources: %w", errors.Join(causes...))
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
