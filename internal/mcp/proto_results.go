package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	mcpv1 "github.com/temporalio/deputy/gen/deputy/mcp/v1"
	remediationv1 "github.com/temporalio/deputy/gen/deputy/remediation/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/analysis/advisorysource"
	"github.com/temporalio/deputy/internal/mcp/protoschema"
	"github.com/temporalio/deputy/internal/otel"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/vulnerability"
	vulnseverity "github.com/temporalio/deputy/internal/vulnerability/severity"
)

// This file adapts tool handlers to the deputy.mcp.v1 proto contracts: results
// are proto messages marshaled with the MCP protojson dialect and returned as
// json.RawMessage (the SDK embeds them in structuredContent verbatim and
// validates them against the descriptor-derived output schema), and inputs are
// unmarshaled from the raw arguments into the request protos. The protojson
// dialect omits zero values of plain fields (absent means empty or not
// applicable); affirmative answers use proto3 optional and are always set,
// so they are always on the wire.

// marshalMCPResult marshals an mcp.v1 result with the canonical MCP dialect.
func marshalMCPResult(m proto.Message) (json.RawMessage, error) {
	data, err := internalproto.MCPJSONMarshalOptions().Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", m.ProtoReflect().Descriptor().FullName(), err)
	}
	return data, nil
}

// unmarshalMCPRequest parses raw tool arguments into an mcp.v1 request proto
// and enforces the request's buf.validate rules with protovalidate, the same
// rules the derived input schema advertises. In production the MCP SDK has
// already validated the arguments against that schema, so this is defense in
// depth: it makes the handlers self-contained (direct invocations get the
// same contract) and rejects unknown fields, mirroring the schema's
// additionalProperties: false.
func unmarshalMCPRequest(raw json.RawMessage, m proto.Message) error {
	// Empty raw means the tool was invoked with no arguments; validation
	// still runs on the zero message so required fields reject as absent.
	if len(raw) > 0 {
		if err := (internalproto.MCPJSONUnmarshalOptions()).Unmarshal(raw, m); err != nil {
			return fmt.Errorf("parse arguments: %w", err)
		}
	}
	if err := internalproto.Validate(m); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

// mustToolSchemas derives a tool's input and output schemas from its mcp.v1
// request and result descriptors at registration time. Generation failures are
// programmer errors in the proto contracts (oneofs, recursion), so panic with
// the cause rather than registering a tool whose schema silently disagrees
// with its wire.
func mustToolSchemas(request, result protoreflect.MessageDescriptor) (in, out *jsonschema.Schema) {
	in, err := protoschema.ForMessage(request, protoschema.Options{Input: true})
	if err != nil {
		panic(fmt.Sprintf("mcp: input schema for %s: %v", request.FullName(), err))
	}
	out, err = protoschema.ForMessage(result, protoschema.Options{})
	if err != nil {
		panic(fmt.Sprintf("mcp: output schema for %s: %v", result.FullName(), err))
	}
	return in, out
}

// runTool executes one MCP tool call with the lifecycle every tool shares:
// the category timeout, the tool span, request parsing and protovalidate
// enforcement, result marshaling, and a call metric recorded on every exit
// path. Owning the lifecycle in one place makes the per-tool observability
// impossible to get wrong per handler: a tool cannot forget its failure
// metric or skip its span. impl returns the result message to put on the
// wire and reads the span from ctx (otel.SpanFromContext) for tool-specific
// attributes.
func runTool[Req proto.Message](
	ctx context.Context,
	s *Server,
	tool string,
	timeout time.Duration,
	req Req,
	raw json.RawMessage,
	impl func(context.Context, Req) (proto.Message, error),
) (*mcp.CallToolResult, json.RawMessage, error) {
	startTime := time.Now()
	ctx, cancel := s.withTimeout(ctx, timeout)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp."+tool,
		trace.WithAttributes(otel.AttrMCPTool.String(tool)))
	defer span.End()

	success := false
	defer func() {
		otel.RecordMCPToolCall(ctx, tool, time.Since(startTime).Seconds(), success)
	}()

	if err := unmarshalMCPRequest(raw, req); err != nil {
		otel.SetSpanError(span, err)
		return nil, nil, err
	}
	result, err := impl(ctx, req)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, nil, err
	}
	out, err := marshalMCPResult(result)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, nil, err
	}
	otel.SetSpanOK(span)
	success = true
	return nil, out, nil
}

// vulnExplanationProto builds the mcp.v1 projection of a consolidated finding.
func vulnExplanationProto(v vulnerability.Consolidated, opts vulnExplanationOptions) *mcpv1.VulnExplanation {
	refs, truncated := referencesForMCP(v.References, opts.referenceLimit)
	out := &mcpv1.VulnExplanation{
		Id:            v.PrimaryID,
		Aliases:       stringsForMCP(v.SecondaryIDs),
		Summary:       v.Summary,
		Kind:          mcpFindingKind(v.Kind),
		Severity:      severityStringForMCP(v.Severity, v.SeverityType),
		SeverityType:  strings.TrimSpace(v.SeverityType),
		Sources:       stringsForMCP(v.Sources),
		FixedVersions: stringsForMCP(v.FixedVersions),
		PackageFixes:  packageFixesProto(v.PackageFixes),
		ResolvedFix:   fixVerdictProto(v.Fix),
		References:    refs,
		Published:     v.Published,
		Modified:      v.Modified,
	}
	if opts.includeDetails {
		out.Details = v.Details
	}
	if truncated {
		out.ReferenceCount = int32(len(v.References))
		out.ReferencesTruncated = true
	}
	return out
}

// advisoryExplanationProto builds the mcp.v1 explanation of a raw advisory for
// the explain tools: full details are always included, and reference lists are
// truncated only when the caller asked for a limit. Kind and severityType
// carry over from the advisory so a malicious-package record is never
// presented as an ordinary vulnerability; sources is always OSV because
// advisory lookups are served by the OSV-backed vulnerability service.
func advisoryExplanationProto(advisory *vulnerabilityv1.Advisory, referenceLimit int) *mcpv1.VulnExplanation {
	if advisory == nil {
		return &mcpv1.VulnExplanation{Severity: "UNKNOWN"}
	}

	_, severityType := vulnseverity.Strings(advisory.GetSeverity())
	refs, truncated := referencesForMCP(advisory.GetReferences(), referenceLimit)
	out := &mcpv1.VulnExplanation{
		Id:            advisory.GetId(),
		Aliases:       stringsForMCP(advisory.GetAliases()),
		Summary:       advisory.GetSummary(),
		Details:       advisory.GetDetails(),
		Kind:          mcpFindingKind(advisory.GetKind()),
		Severity:      protoSeverityStringForMCP(advisory.GetSeverity()),
		SeverityType:  strings.TrimSpace(severityType),
		Sources:       []string{advisorysource.SourceNameOSV},
		FixedVersions: stringsForMCP(advisory.GetFixedVersions()),
		PackageFixes:  packageFixesProto(advisory.GetPackageFixes()),
		ResolvedFix:   protoFixVerdictProto(advisory.GetResolvedFix()),
		References:    refs,
	}
	if truncated {
		out.ReferenceCount = int32(len(advisory.GetReferences()))
		out.ReferencesTruncated = true
	}
	if advisory.GetPublished() != nil {
		out.Published = advisory.GetPublished().AsTime().Format(time.RFC3339)
	}
	if advisory.GetModified() != nil {
		out.Modified = advisory.GetModified().AsTime().Format(time.RFC3339)
	}
	return out
}

// protoFixVerdictProto converts an advisory's resolved fix verdict to the
// mcp.v1 shape. Nil or unspecified verdicts are omitted.
func protoFixVerdictProto(v *vulnerabilityv1.FixVerdict) *mcpv1.FixVerdict {
	if v == nil || v.GetStatus() == vulnerabilityv1.FixVerdict_STATUS_UNSPECIFIED {
		return nil
	}
	return &mcpv1.FixVerdict{
		Status:       protoFixStatusString(v.GetStatus()),
		Version:      v.GetVersion(),
		TargetModule: v.GetTargetModule(),
		Claimed:      v.GetClaimed(),
	}
}

// packageFixesProto converts advisory package fixes to the mcp.v1 shape.
func packageFixesProto(fixes []*vulnerabilityv1.PackageFix) []*mcpv1.PackageFix {
	if len(fixes) == 0 {
		return nil
	}
	out := make([]*mcpv1.PackageFix, 0, len(fixes))
	for _, f := range fixes {
		if f == nil {
			continue
		}
		out = append(out, &mcpv1.PackageFix{
			Module:        f.GetModule(),
			Ecosystem:     mcpOutputEcosystem(f.GetEcosystem()),
			FixedVersions: stringsForMCP(f.GetFixedVersions()),
		})
	}
	return out
}

// fixVerdictProto converts a resolved fix verdict to the mcp.v1 shape. Nil or
// unknown verdicts are omitted, matching the previous omitempty behavior.
func fixVerdictProto(v *vulnerability.FixVerdict) *mcpv1.FixVerdict {
	if v == nil || v.Status == vulnerability.FixStatusUnknown {
		return nil
	}
	return &mcpv1.FixVerdict{
		Status:       fixStatusString(v.Status),
		Version:      v.Version,
		TargetModule: v.TargetModule,
		Claimed:      v.Claimed,
	}
}

// remediationStepProto projects a deputy.remediation.v1 plan step onto the
// mcp.v1 wire: kind and risk become lowercase strings, and the affirmative
// migration/direct/executable answers get explicit presence.
func remediationStepProto(step *remediationv1.Step) *mcpv1.RemediationStep {
	if step == nil {
		return nil
	}
	return &mcpv1.RemediationStep{
		Id:                      step.GetId(),
		Kind:                    stepKindString(step.GetKind()),
		Title:                   step.GetTitle(),
		Description:             step.GetDescription(),
		Package:                 step.GetPackageName(),
		Purl:                    step.GetPurl(),
		Version:                 step.GetCurrentVersion(),
		TargetVersion:           step.GetTargetVersion(),
		TargetModule:            step.GetTargetModule(),
		Migration:               proto.Bool(step.GetMigration()),
		Manager:                 step.GetManager(),
		ManifestPath:            step.GetManifestPath(),
		Command:                 step.GetCommand(),
		Hint:                    step.GetHint(),
		Direct:                  proto.Bool(step.GetDirect()),
		Executable:              proto.Bool(step.GetExecutable()),
		Groups:                  step.GetGroups(),
		RiskLevel:               internalproto.RiskLevelFromProto(step.GetRiskLevel()),
		AffectedVulnerabilities: step.GetAffectedVulnerabilities(),
	}
}

// stepKindString maps plan step kinds onto the lowercase mcp.v1 wire values;
// unspecified maps to empty and is omitted.
func stepKindString(kind remediationv1.StepKind) string {
	switch kind {
	case remediationv1.StepKind_STEP_KIND_VERSION_UPGRADE:
		return "version_upgrade"
	case remediationv1.StepKind_STEP_KIND_FILE_EDIT:
		return "file_edit"
	case remediationv1.StepKind_STEP_KIND_SHELL_COMMAND:
		return "shell_command"
	case remediationv1.StepKind_STEP_KIND_DOCKERFILE_UPDATE:
		return "dockerfile_update"
	case remediationv1.StepKind_STEP_KIND_ACTION_UPDATE:
		return "action_update"
	case remediationv1.StepKind_STEP_KIND_CONFIG_CHANGE:
		return "config_change"
	case remediationv1.StepKind_STEP_KIND_CUSTOM_AGENT:
		return "custom_agent"
	default:
		return ""
	}
}

// manifestRefsProto normalizes manifest declarations for the mcp.v1 wire:
// values are whitespace-trimmed and entries with nothing to report are
// dropped, matching the previous omit-empty behavior.
func manifestRefsProto(refs []*dependencyv1.ManifestRef) []*dependencyv1.ManifestRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]*dependencyv1.ManifestRef, 0, len(refs))
	for _, ref := range refs {
		if ref == nil {
			continue
		}
		path := strings.TrimSpace(ref.GetPath())
		manager := strings.TrimSpace(ref.GetManager())
		componentKey := strings.TrimSpace(ref.GetComponentKey())
		groups := stringsForMCP(ref.GetGroups())
		if path == "" && manager == "" && componentKey == "" && len(groups) == 0 {
			continue
		}
		out = append(out, &dependencyv1.ManifestRef{
			Path:         path,
			Manager:      manager,
			Groups:       groups,
			ComponentKey: componentKey,
		})
	}
	return out
}

// coverageProto converts scan coverage to the mcp.v1 shape. Returns nil when
// there is nothing to report so the field is omitted.
func coverageProto(c *vulnerabilityv1.ScanCoverage) *mcpv1.Coverage {
	if c == nil || (len(c.GetCovered()) == 0 && len(c.GetUncovered()) == 0) {
		return nil
	}
	conv := func(entries []*vulnerabilityv1.CoverageEntry) []*mcpv1.CoverageEntry {
		out := make([]*mcpv1.CoverageEntry, 0, len(entries))
		for _, e := range entries {
			if e == nil {
				continue
			}
			out = append(out, &mcpv1.CoverageEntry{
				Ecosystem:    e.GetEcosystem(),
				Artifact:     mcpArtifactKind(e.GetArtifact()),
				Sources:      e.GetSources(),
				PackageCount: e.GetPackageCount(),
			})
		}
		return out
	}
	return &mcpv1.Coverage{Covered: conv(c.GetCovered()), Uncovered: conv(c.GetUncovered())}
}
