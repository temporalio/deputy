package descriptorset

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestCommentLookup(t *testing.T) {
	tests := []struct {
		name string
		want string // substring of the .proto leading comment
	}{
		{"deputy.vulnerability.v1.Advisory", "vulnerability as published"},
		{"deputy.vulnerability.v1.Advisory.kind", "malware"},
		{"deputy.vulnerability.v1.FindingKind", "class of security issue"},
		{"deputy.vulnerability.v1.CoverageEntry.ecosystem", "canonical name"},
		{"deputy.triage.v1.PackageSummary.priority", "canonical triage"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Comment(protoreflect.FullName(tt.name))
			if got == "" {
				t.Fatalf("Comment(%s) empty; comments not indexed", tt.name)
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("Comment(%s) = %q, want substring %q", tt.name, got, tt.want)
			}
		})
	}
	if got := Comment("deputy.nonexistent.v1.Nope"); got != "" {
		t.Fatalf("unknown element should return empty, got %q", got)
	}
}

// TestScalarMapFields pins the derived view of map fields: opaque key/value
// maps are recognized, maps whose values are messages are not, and neither are
// plain repeated or singular fields.
func TestScalarMapFields(t *testing.T) {
	tests := []struct {
		field string
		want  bool
	}{
		{field: "custom_claims", want: true},     // policy.v1.JWTClaims, map<string, string>
		{field: "labels", want: true},            // container.v1.ImageConfig, map<string, string>
		{field: "database_specific", want: true}, // vulnerability.v1.Advisory, map<string, string>
		{field: "provenance", want: true},        // target.v1.Target, map<string, string>
		{field: "ecosystems", want: true},        // count map, map<string, int32>
		{field: "advisories", want: false},       // map<string, Advisory>
		{field: "fixed_versions", want: false},   // repeated string
		{field: "ecosystem", want: false},        // string
		{field: "made_up_field", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			if got := IsScalarMapField(tt.field); got != tt.want {
				t.Errorf("IsScalarMapField(%q) = %t, want %t (set: %v)", tt.field, got, tt.want, ScalarMapFieldNames())
			}
		})
	}
}
