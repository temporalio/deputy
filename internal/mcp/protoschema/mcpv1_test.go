package protoschema

import (
	"slices"
	"strings"
	"testing"

	mcpv1 "github.com/temporalio/deputy/gen/deputy/mcp/v1"
)

// TestScanDirectoryRequestSchema exercises the buf.validate-driven input
// mappings against the real deputy.mcp.v1 request contract.
func TestScanDirectoryRequestSchema(t *testing.T) {
	schema, err := ForMessage((&mcpv1.ScanDirectoryRequest{}).ProtoReflect().Descriptor(), Options{Input: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(schema.Required, "path") {
		t.Errorf("required = %v, want to include path (buf.validate required)", schema.Required)
	}
	path := schema.Properties["path"]
	if path == nil || path.MinLength == nil || *path.MinLength != 1 || path.Pattern != `\S` {
		t.Errorf("path = %+v, want minLength 1 and pattern \\S from string rules", path)
	}
	if !strings.Contains(path.Description, "directory to scan") {
		t.Errorf("path description not from proto comment: %q", path.Description)
	}
	if schema.AdditionalProperties == nil || schema.AdditionalProperties.Not == nil {
		t.Error("request schema must set additionalProperties: false")
	}
	// Optional fields must not be required.
	for _, opt := range []string{"ref", "ecosystems", "excludePaths"} {
		if slices.Contains(schema.Required, opt) {
			t.Errorf("%s must not be required", opt)
		}
		if schema.Properties[opt] == nil {
			t.Errorf("missing optional property %s", opt)
		}
	}
}

// TestTriagedVulnSchema verifies string.in lists become schema enums with the
// agent-facing lowercase wire values.
func TestTriagedVulnSchema(t *testing.T) {
	schema, err := ForMessage((&mcpv1.TriagedVuln{}).ProtoReflect().Descriptor(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	prio := schema.Properties["priority"]
	if prio == nil {
		t.Fatal("missing priority property")
	}
	for _, want := range []string{"critical", "high", "medium", "low"} {
		if !enumContains(prio.Enum, want) {
			t.Errorf("priority enum missing %q: %v", want, prio.Enum)
		}
	}
	if kind := schema.Properties["kind"]; kind == nil || !enumContains(kind.Enum, "malware") {
		t.Errorf("kind enum should carry lowercase wire values, got %+v", kind)
	}
	if fv := schema.Properties["resolvedFix"]; fv == nil || !enumContains(fv.Properties["status"].Enum, "migration") {
		t.Errorf("resolvedFix.status should enumerate verdicts, got %+v", fv)
	}
}

// TestScanDirectoryResultSchema verifies result-side shapes: severity map,
// int32 counts as JSON integers, and permissive additionalProperties.
func TestScanDirectoryResultSchema(t *testing.T) {
	schema, err := ForMessage((&mcpv1.ScanDirectoryResult{}).ProtoReflect().Descriptor(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if sev := schema.Properties["vulnerabilitiesBySeverity"]; sev == nil || sev.Type != "object" || sev.AdditionalProperties == nil || sev.AdditionalProperties.Type != "integer" {
		t.Errorf("vulnerabilitiesBySeverity = %+v, want map of integers", sev)
	}
	if ms := schema.Properties["scanTimeMs"]; ms == nil || ms.Type != "integer" {
		t.Errorf("scanTimeMs = %+v, want integer (int32 keeps JSON numbers)", ms)
	}
	if cov := schema.Properties["coverage"]; cov == nil || cov.Properties["uncovered"] == nil {
		t.Errorf("coverage should inline Coverage with covered/uncovered")
	}
	if schema.AdditionalProperties != nil {
		t.Error("result schema must stay permissive")
	}
}
