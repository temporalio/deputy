package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	mcpv1 "github.com/temporalio/deputy/gen/deputy/mcp/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/mcp/protoschema"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// This file adapts tool handlers to the deputy.mcp.v1 proto contracts: results
// are proto messages marshaled with the MCP protojson dialect and returned as
// json.RawMessage (the SDK embeds them in structuredContent verbatim and
// validates them against the descriptor-derived output schema), and inputs are
// unmarshaled from the raw arguments into the request protos. Absent fields
// mean empty/zero — the protojson dialect omits zero values.

// marshalMCPResult marshals an mcp.v1 result with the canonical MCP dialect.
func marshalMCPResult(m proto.Message) (json.RawMessage, error) {
	data, err := internalproto.MCPJSONMarshalOptions().Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", m.ProtoReflect().Descriptor().FullName(), err)
	}
	return data, nil
}

// unmarshalMCPRequest parses the SDK-validated raw arguments into an mcp.v1
// request proto. Unknown fields are rejected: the input schema already
// advertises additionalProperties: false, so this is defense in depth.
func unmarshalMCPRequest(raw json.RawMessage, m proto.Message) error {
	if len(raw) == 0 {
		return nil
	}
	if err := (internalproto.MCPJSONUnmarshalOptions()).Unmarshal(raw, m); err != nil {
		return fmt.Errorf("parse arguments: %w", err)
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
