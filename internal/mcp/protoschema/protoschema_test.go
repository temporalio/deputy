package protoschema

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

func TestForMessageAdvisory(t *testing.T) {
	schema, err := ForMessage((&vulnerabilityv1.Advisory{}).ProtoReflect().Descriptor(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if schema.Type != "object" {
		t.Fatalf("type = %q, want object", schema.Type)
	}
	// camelCase property names (protojson wire dialect).
	for _, want := range []string{"fixedVersions", "packageFixes", "databaseSpecific", "resolvedFix", "kind"} {
		if schema.Properties[want] == nil {
			t.Errorf("missing property %q; have %v", want, propertyNames(schema))
		}
	}
	// Proto enum field renders as string enum of declared value names.
	kind := schema.Properties["kind"]
	if kind.Type != "string" || !enumContains(kind.Enum, "FINDING_KIND_MALWARE") {
		t.Errorf("kind schema = %+v, want string enum incl. FINDING_KIND_MALWARE", kind)
	}
	// Timestamp renders as string.
	if got := schema.Properties["published"]; got == nil || got.Type != "string" {
		t.Errorf("published = %+v, want string (RFC 3339)", got)
	}
	// map<string,string> renders as object with string additionalProperties.
	ds := schema.Properties["databaseSpecific"]
	if ds == nil || ds.Type != "object" || ds.AdditionalProperties == nil || ds.AdditionalProperties.Type != "string" {
		t.Errorf("databaseSpecific = %+v, want object with string values", ds)
	}
	// Nested message inlined (no $ref).
	if rf := schema.Properties["resolvedFix"]; rf == nil || rf.Type != "object" || len(rf.Properties) == 0 {
		t.Errorf("resolvedFix should inline FixVerdict as an object with properties")
	}
	// Descriptions come from the .proto comments.
	if !strings.Contains(schema.Description, "vulnerability as published") {
		t.Errorf("message description not sourced from proto comment: %q", schema.Description)
	}
	if !strings.Contains(schema.Properties["kind"].Description, "malware") {
		t.Errorf("field description not sourced from proto comment: %q", schema.Properties["kind"].Description)
	}
}

func TestForMessageCoverageEntry(t *testing.T) {
	schema, err := ForMessage((&vulnerabilityv1.CoverageEntry{}).ProtoReflect().Descriptor(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := schema.Properties["packageCount"]; got == nil || got.Type != "integer" {
		t.Errorf("packageCount = %+v, want integer (int32)", got)
	}
	if got := schema.Properties["sources"]; got == nil || got.Type != "array" || got.Items == nil || got.Items.Type != "string" {
		t.Errorf("sources = %+v, want array of string", got)
	}
	if got := schema.Properties["artifact"]; got == nil || !enumContains(got.Enum, "ARTIFACT_KIND_PACKAGE") {
		t.Errorf("artifact = %+v, want enum incl. ARTIFACT_KIND_PACKAGE", got)
	}
}

func TestInputOptionsStrictness(t *testing.T) {
	md := (&vulnerabilityv1.CoverageEntry{}).ProtoReflect().Descriptor()
	input, err := ForMessage(md, Options{Input: true})
	if err != nil {
		t.Fatal(err)
	}
	if input.AdditionalProperties == nil || input.AdditionalProperties.Not == nil {
		t.Error("input schema must reject unknown properties (additionalProperties: false)")
	}
	output, err := ForMessage(md, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if output.AdditionalProperties != nil {
		t.Error("output schema must stay permissive so additive fields don't fail SDK output validation")
	}
}

func TestOneofRejected(t *testing.T) {
	_, err := ForMessage((&policyv1.EvaluateRequest{}).ProtoReflect().Descriptor(), Options{Input: true})
	if err == nil || !strings.Contains(err.Error(), "oneof") {
		t.Fatalf("expected oneof rejection, got %v", err)
	}
}

// TestNoClientRejectedKeywords guards the constraint that broke tool loading in
// production: nothing the generator emits may contain $ref or oneOf/anyOf/allOf
// at any level.
func TestNoClientRejectedKeywords(t *testing.T) {
	cases := map[string]*jsonschema.Schema{}
	for name, gen := range map[string]func() (*jsonschema.Schema, error){
		"advisory": func() (*jsonschema.Schema, error) {
			return ForMessage((&vulnerabilityv1.Advisory{}).ProtoReflect().Descriptor(), Options{})
		},
		"coverage": func() (*jsonschema.Schema, error) {
			return ForMessage((&vulnerabilityv1.ScanCoverage{}).ProtoReflect().Descriptor(), Options{})
		},
	} {
		s, err := gen()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		cases[name] = s
	}

	for name, s := range cases {
		raw, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, banned := range []string{`"$ref"`, `"oneOf"`, `"anyOf"`, `"allOf"`} {
			if strings.Contains(string(raw), banned) {
				t.Errorf("%s schema contains %s, which MCP clients reject", name, banned)
			}
		}
	}
}

func propertyNames(s *jsonschema.Schema) []string {
	names := make([]string, 0, len(s.Properties))
	for k := range s.Properties {
		names = append(names, k)
	}
	slices.Sort(names)
	return names
}

func enumContains(enum []any, want string) bool {
	for _, v := range enum {
		if s, ok := v.(string); ok && s == want {
			return true
		}
	}
	return false
}
