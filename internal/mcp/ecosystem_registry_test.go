package mcp

import (
	"testing"

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
