package ecosystem

import (
	"slices"
	"testing"
)

func TestCanonical(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		want      string
		wantKnown bool
	}{
		{name: "empty", raw: "", want: "", wantKnown: false},
		{name: "whitespace only", raw: "   ", want: "", wantKnown: false},
		{name: "already canonical", raw: "go", want: "go", wantKnown: true},
		{name: "go display name", raw: "Go", want: "go", wantKnown: true},
		{name: "go alias", raw: "golang", want: "go", wantKnown: true},
		{name: "pypi display name", raw: "PyPI", want: "pypi", wantKnown: true},
		{name: "rubygems display name", raw: "RubyGems", want: "rubygems", wantKnown: true},
		{name: "cargo osv name", raw: "crates.io", want: "cargo", wantKnown: true},
		{name: "cargo osv name with suffix", raw: "cargo (crates.io)", want: "cargo", wantKnown: true},
		{name: "github actions display name", raw: "GitHub Actions", want: "github-actions", wantKnown: true},
		{name: "github actions alias", raw: "gha", want: "github-actions", wantKnown: true},
		{name: "github actions underscored", raw: "github_actions", want: "github-actions", wantKnown: true},
		{name: "docker", raw: "docker", want: "docker", wantKnown: true},
		{name: "dockerfile alias", raw: "Dockerfile", want: "docker", wantKnown: true},
		{name: "oci stays distinct from docker", raw: "OCI", want: "oci", wantKnown: true},
		{name: "mise", raw: "mise", want: "mise", wantKnown: true},
		{name: "padded input", raw: "  npm  ", want: "npm", wantKnown: true},
		{name: "os ecosystem falls back to slug", raw: "Alpine:v3.19", want: "alpine:v3.19", wantKnown: false},
		{name: "multiword unknown folds spaces", raw: "Red Hat", want: "red-hat", wantKnown: false},
		{name: "unknown stays lowercase", raw: "Fictional", want: "fictional", wantKnown: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, known := Canonical(tt.raw)
			if got != tt.want || known != tt.wantKnown {
				t.Errorf("Canonical(%q) = (%q, %t), want (%q, %t)", tt.raw, got, known, tt.want, tt.wantKnown)
			}
			if or := CanonicalOrRaw(tt.raw); or != tt.want {
				t.Errorf("CanonicalOrRaw(%q) = %q, want %q", tt.raw, or, tt.want)
			}
			if ok := IsCanonical(tt.raw); ok != tt.wantKnown {
				t.Errorf("IsCanonical(%q) = %t, want %t", tt.raw, ok, tt.wantKnown)
			}
		})
	}
}

// TestCanonicalIsIdempotent pins the round-trip property policies depend on:
// feeding a canonical token back through Canonical must not change it, which is
// what lets display forms with separators ("GitHub Actions") be compared
// against their token form.
func TestCanonicalIsIdempotent(t *testing.T) {
	for _, token := range CanonicalEcosystems() {
		t.Run(token, func(t *testing.T) {
			got, known := Canonical(token)
			if !known {
				t.Fatalf("Canonical(%q) reported unknown for a canonical token", token)
			}
			if got != token {
				t.Fatalf("Canonical(%q) = %q, want the token unchanged", token, got)
			}
		})
	}
}

func TestCanonicalEcosystems(t *testing.T) {
	tokens := CanonicalEcosystems()
	if !slices.IsSorted(tokens) {
		t.Errorf("CanonicalEcosystems() = %v, want sorted", tokens)
	}
	for _, want := range []string{"go", "npm", "pypi", "cargo", "mise", "docker", "github-actions", "oci"} {
		if !slices.Contains(tokens, want) {
			t.Errorf("CanonicalEcosystems() missing %q: %v", want, tokens)
		}
	}
	for _, unwanted := range []string{"Go", "GitHub Actions", "unknown", ""} {
		if slices.Contains(tokens, unwanted) {
			t.Errorf("CanonicalEcosystems() contains non-canonical %q: %v", unwanted, tokens)
		}
	}
}
