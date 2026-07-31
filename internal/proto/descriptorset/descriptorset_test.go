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
