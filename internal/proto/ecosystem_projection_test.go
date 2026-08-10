package proto

import (
	"testing"

	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/purlx"
)

// TestEcosystemFromPURLTypeDerivesFromRegistry pins that the ecosystem names
// this package stamps onto packages come from the ecosystem registry. The
// expectations are computed, not literals, so hardcoding a spelling here again
// fails as soon as it disagrees with the registry, and every emitted name
// resolves back to its canonical token.
func TestEcosystemFromPURLTypeDerivesFromRegistry(t *testing.T) {
	tests := []struct {
		name     string
		purlType string
		want     ecosystem.Ecosystem
	}{
		{name: "github actions", purlType: purlx.TypeGitHubActions, want: ecosystem.GitHubActions},
		{name: "mise", purlType: purlx.TypeMise, want: ecosystem.Mise},
		{name: "asdf", purlType: purlx.TypeAsdf, want: ecosystem.Asdf},
		{name: "docker", purlType: "docker", want: ecosystem.Docker},
		{name: "oci", purlType: "oci", want: ecosystem.OCI},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ecosystemFromPURLType(tt.purlType)
			if want := ecosystem.Display(tt.want); got != want {
				t.Errorf("ecosystemFromPURLType(%q) = %q, want the registry display name %q", tt.purlType, got, want)
			}
			token, known := ecosystem.Canonical(got)
			if !known || token != string(tt.want) {
				t.Errorf("ecosystemFromPURLType(%q) = %q, which resolves to (%q, %t), want (%q, true)",
					tt.purlType, got, token, known, tt.want)
			}
		})
	}
}

// TestEcosystemFromPURLTypeIgnoresHandledTypes keeps the fallback narrow: types
// OSV-SCALIBR names itself must return empty so the SCALIBR ecosystem wins.
func TestEcosystemFromPURLTypeIgnoresHandledTypes(t *testing.T) {
	for _, purlType := range []string{"golang", "npm", "pypi", "", "unheard-of"} {
		t.Run(purlType, func(t *testing.T) {
			if got := ecosystemFromPURLType(purlType); got != "" {
				t.Errorf("ecosystemFromPURLType(%q) = %q, want empty", purlType, got)
			}
		})
	}
}
