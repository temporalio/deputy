package policy

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeEcosystem(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "canonical passes through", in: "go", want: "go"},
		{name: "display name folds", in: "Go", want: "go"},
		{name: "alias resolves", in: "golang", want: "go"},
		{name: "pypi display name", in: "PyPI", want: "pypi"},
		{name: "github actions display name", in: "GitHub Actions", want: "github-actions"},
		{name: "osv cargo name", in: "crates.io", want: "cargo"},
		{name: "unknown still folds casing", in: "Alpine:v3.19", want: "alpine:v3.19"},
		{name: "empty", in: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NormalizeEcosystem(tt.in); got != tt.want {
				t.Errorf("NormalizeEcosystem(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateEcosystems(t *testing.T) {
	tests := []struct {
		name    string
		in      []string
		want    []string
		wantErr string
	}{
		{name: "nil", in: nil, want: nil},
		{name: "canonical", in: []string{"go", "npm"}, want: []string{"go", "npm"}},
		{name: "display casing normalizes", in: []string{"Go", "PyPI"}, want: []string{"go", "pypi"}},
		{name: "aliases normalize", in: []string{"golang", "GitHub Actions"}, want: []string{"go", "github-actions"}},
		{name: "duplicate spellings collapse", in: []string{"Go", "go", "golang"}, want: []string{"go"}},
		{name: "unknown rejected", in: []string{"go", "kubernetes"}, wantErr: `invalid ecosystem "kubernetes"`},
		{name: "os ecosystem rejected", in: []string{"Alpine:v3.19"}, wantErr: `invalid ecosystem "Alpine:v3.19"`},
		{name: "empty rejected", in: []string{""}, wantErr: `invalid ecosystem ""`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateEcosystems(tt.in)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("validateEcosystems(%v) = %v, want error containing %q", tt.in, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("validateEcosystems(%v) error = %v, want it to contain %q", tt.in, err, tt.wantErr)
				}
				if !strings.Contains(err.Error(), "expected one of:") || !strings.Contains(err.Error(), "github-actions") {
					t.Errorf("validateEcosystems(%v) error = %v, want it to name the valid set", tt.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateEcosystems(%v): %v", tt.in, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("validateEcosystems(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestProxyEntrypoint(t *testing.T) {
	tests := []struct {
		name string
		eco  string
		want Entrypoint
	}{
		{name: "go", eco: "go", want: EntrypointGoArtifactRequest},
		{name: "npm", eco: "npm", want: EntrypointNpmArtifactRequest},
		{name: "pypi", eco: "pypi", want: EntrypointPypiArtifactRequest},
		{name: "rubygems", eco: "rubygems", want: EntrypointRubygemsArtifactRequest},
		{name: "oci", eco: "oci", want: EntrypointOCIArtifactRequest},
		{name: "display casing resolves", eco: "PyPI", want: EntrypointPypiArtifactRequest},
		{name: "alias resolves", eco: "golang", want: EntrypointGoArtifactRequest},
		{name: "no proxy entrypoint", eco: "maven", want: ""},
		{name: "empty", eco: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProxyEntrypoint(tt.eco); got != tt.want {
				t.Errorf("ProxyEntrypoint(%q) = %q, want %q", tt.eco, got, tt.want)
			}
		})
	}
}

func TestCanonicalizeEcosystemPayload(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
		want    map[string]any
	}{
		{
			name:    "package ecosystem",
			payload: map[string]any{"pkg": map[string]any{"name": "x", "ecosystem": "Go"}},
			want:    map[string]any{"pkg": map[string]any{"name": "x", "ecosystem": "go"}},
		},
		{
			name:    "proxy request ecosystem",
			payload: map[string]any{"request": map[string]any{"ecosystem": "RubyGems"}},
			want:    map[string]any{"request": map[string]any{"ecosystem": "rubygems"}},
		},
		{
			name: "nested vulnerability package",
			payload: map[string]any{"vulnerabilities": []any{
				map[string]any{"package": map[string]any{"ecosystem": "GitHub Actions"}},
			}},
			want: map[string]any{"vulnerabilities": []any{
				map[string]any{"package": map[string]any{"ecosystem": "github-actions"}},
			}},
		},
		{
			name:    "ecosystem list",
			payload: map[string]any{"config": map[string]any{"ecosystems": []any{"Go", "crates.io"}}},
			want:    map[string]any{"config": map[string]any{"ecosystems": []any{"go", "cargo"}}},
		},
		{
			name:    "ecosystem string slice",
			payload: map[string]any{"config": map[string]any{"ecosystems": []string{"Go", "npm"}}},
			want:    map[string]any{"config": map[string]any{"ecosystems": []string{"go", "npm"}}},
		},
		{
			name:    "stats count map keys",
			payload: map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"Go": 2.0, "GitHub Actions": 1.0}}},
			want:    map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"go": 2.0, "github-actions": 1.0}}},
		},
		{
			name:    "stats count map merges colliding spellings",
			payload: map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"Go": 2.0, "go": 3.0}}},
			want:    map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"go": 5.0}}},
		},
		{
			name:    "json numbers merge",
			payload: map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"Go": json.Number("2"), "golang": json.Number("1")}}},
			want:    map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"go": 3.0}}},
		},
		{
			name:    "non-string ecosystem left alone",
			payload: map[string]any{"pkg": map[string]any{"ecosystem": nil}},
			want:    map[string]any{"pkg": map[string]any{"ecosystem": nil}},
		},
		{
			name:    "unrelated fields untouched",
			payload: map[string]any{"pkg": map[string]any{"name": "GitHub Actions", "version": "V1"}},
			want:    map[string]any{"pkg": map[string]any{"name": "GitHub Actions", "version": "V1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonicalizeEcosystemPayload(tt.payload)
			if !reflect.DeepEqual(tt.payload, tt.want) {
				t.Errorf("canonicalizeEcosystemPayload() = %#v, want %#v", tt.payload, tt.want)
			}
		})
	}
}

// TestStructuredBundleRejectsUnknownEcosystem pins the load-time contract: an
// ecosystems: value Deputy does not know is an error naming the offending value
// and the valid set, and a known one is rewritten to its canonical token in
// both the generated guard and the metadata comment.
func TestStructuredBundleEcosystemValidation(t *testing.T) {
	tests := []struct {
		name     string
		bundle   string
		wantErr  string
		wantCEL  []string
		wantSkip []string
	}{
		{
			name: "display casing is accepted and canonicalized",
			bundle: `policies:
  - name: display-cased
    ecosystems: ["Go", "GitHub Actions"]
    rules:
      - action: deny
        when: pkg.name == "x"
`,
			wantCEL:  []string{`"go","github-actions"`, `//! policy.ecosystems = "go,github-actions"`},
			wantSkip: []string{`"Go"`, `"GitHub Actions"`},
		},
		{
			name: "unknown ecosystem is a load error",
			bundle: `policies:
  - name: bogus
    ecosystems: ["kubernetes"]
    rules:
      - action: deny
        when: pkg.name == "x"
`,
			wantErr: `invalid ecosystem "kubernetes"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sources, err := ParseStructuredSources([]byte(tt.bundle), "test.yaml")
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseStructuredSources() = %v, want error containing %q", sources, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseStructuredSources() error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseStructuredSources(): %v", err)
			}
			if len(sources) != 1 {
				t.Fatalf("got %d sources, want 1", len(sources))
			}
			body := sources[0].Body
			for _, want := range tt.wantCEL {
				if !strings.Contains(body, want) {
					t.Errorf("generated source missing %q:\n%s", want, body)
				}
			}
			for _, unwanted := range tt.wantSkip {
				if strings.Contains(body, unwanted) {
					t.Errorf("generated source still contains raw spelling %q:\n%s", unwanted, body)
				}
			}
		})
	}
}
