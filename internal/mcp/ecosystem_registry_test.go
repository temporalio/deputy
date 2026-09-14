package mcp

import (
	"slices"
	"testing"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/purlx"
)

// TestCanonicalMCPEcosystemTracksRegistry pins that MCP resolves ecosystem
// names through the shared registry instead of a local alias table. Every
// canonical token, display name, and alias Deputy knows must round-trip, so an
// ecosystem added to the registry is understood by the tools without touching
// this package.
func TestCanonicalMCPEcosystemTracksRegistry(t *testing.T) {
	for _, token := range ecosystem.CanonicalEcosystems() {
		t.Run(token, func(t *testing.T) {
			for _, spelling := range []string{token, ecosystem.Display(ecosystem.Ecosystem(token))} {
				got, ok := canonicalMCPEcosystem(spelling)
				if !ok || got != token {
					t.Errorf("canonicalMCPEcosystem(%q) = (%q, %t), want (%q, true)", spelling, got, ok, token)
				}
			}
		})
	}
}

// TestMCPPURLTypeUsesRegistryToken pins the GitHub Actions purl mapping to the
// registry token rather than a literal.
func TestMCPPURLTypeUsesRegistryToken(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "canonical token", input: ecosystem.GitHubActions.String()},
		{name: "display name", input: ecosystem.Display(ecosystem.GitHubActions)},
		{name: "alias", input: "gha"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mcpPURLType(tt.input); got != purlx.TypeGitHubActions {
				t.Errorf("mcpPURLType(%q) = %q, want %q", tt.input, got, purlx.TypeGitHubActions)
			}
			if got := mcpEcosystemFromPURLType(purlx.TypeGitHubActions); got != ecosystem.GitHubActions.String() {
				t.Errorf("mcpEcosystemFromPURLType(...) = %q, want %q", got, ecosystem.GitHubActions)
			}
		})
	}
}

// emergingPURLTypes are the purl types Deputy emits that the package-url spec
// has not adopted yet, so [TestMCPPURLTypeRoundTrips] can accept them without
// accepting an arbitrary ecosystem token as a type.
var emergingPURLTypes = []string{purlx.TypeGitHubActions, purlx.TypeMise, purlx.TypeAsdf}

// TestMCPPURLTypeRoundTrips is the invariant the ConanCenter defect broke:
// every canonical ecosystem token must render as a purl type the spec (or
// Deputy's documented emerging set) recognizes, and that type must resolve back
// to the same token. A token that emits itself as a purl type when the spec
// spells the type differently ("conancenter" for pkg:conan) produces a target
// nothing can route.
func TestMCPPURLTypeRoundTrips(t *testing.T) {
	for _, token := range ecosystem.CanonicalEcosystems() {
		t.Run(token, func(t *testing.T) {
			purlType := mcpPURLType(token)
			if purlType == "" {
				t.Fatalf("mcpPURLType(%q) is empty", token)
			}
			_, spec := packageurl.KnownTypes[purlType]
			if !spec && !slices.Contains(emergingPURLTypes, purlType) {
				t.Errorf("mcpPURLType(%q) = %q, which is neither a spec purl type nor a documented emerging one", token, purlType)
			}
			if back := mcpEcosystemFromPURLType(purlType); back != token {
				t.Errorf("mcpPURLType(%q) = %q, which resolves back to %q", token, purlType, back)
			}
		})
	}
}

// TestMCPPURLTypeSpecSpellings pins the purl types whose spelling differs from
// the ecosystem token, so a future registry edit cannot quietly emit the token
// where the package-url spec expects its own name.
func TestMCPPURLTypeSpecSpellings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantType string
	}{
		{name: "go", input: "Go", wantType: packageurl.TypeGolang},
		{name: "rubygems", input: "RubyGems", wantType: packageurl.TypeGem},
		{name: "packagist", input: "Packagist", wantType: packageurl.TypeComposer},
		{name: "conan alias", input: "conan", wantType: packageurl.TypeConan},
		{name: "conan token", input: "conancenter", wantType: packageurl.TypeConan},
		{name: "conan display", input: "ConanCenter", wantType: packageurl.TypeConan},
		{name: "cpp alias", input: "cpp", wantType: packageurl.TypeConan},
		{name: "github actions", input: "gha", wantType: purlx.TypeGitHubActions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mcpPURLType(tt.input); got != tt.wantType {
				t.Errorf("mcpPURLType(%q) = %q, want %q", tt.input, got, tt.wantType)
			}
		})
	}
}
