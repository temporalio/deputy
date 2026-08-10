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

func TestCanonicalizeIdentityFields(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
		want    map[string]any
	}{
		{
			name:    "go version gains the v prefix",
			payload: map[string]any{"pkg": map[string]any{"ecosystem": "Go", "name": "github.com/aws/aws-sdk-go", "version": "1.44.0"}},
			want:    map[string]any{"pkg": map[string]any{"ecosystem": "go", "name": "github.com/aws/aws-sdk-go", "version": "v1.44.0"}},
		},
		{
			name:    "go version already prefixed is unchanged",
			payload: map[string]any{"pkg": map[string]any{"ecosystem": "go", "version": "v1.44.0"}},
			want:    map[string]any{"pkg": map[string]any{"ecosystem": "go", "version": "v1.44.0"}},
		},
		{
			name:    "npm version keeps its shape",
			payload: map[string]any{"pkg": map[string]any{"ecosystem": "npm", "name": "Lodash", "version": "4.17.21"}},
			want:    map[string]any{"pkg": map[string]any{"ecosystem": "npm", "name": "Lodash", "version": "4.17.21"}},
		},
		{
			name:    "pypi name is lowercased",
			payload: map[string]any{"pkg": map[string]any{"ecosystem": "PyPI", "name": "Flask-SQLAlchemy", "version": "3.1.1"}},
			want:    map[string]any{"pkg": map[string]any{"ecosystem": "pypi", "name": "flask-sqlalchemy", "version": "3.1.1"}},
		},
		{
			name: "change versions normalize from the nested package",
			payload: map[string]any{"change": map[string]any{
				"package":        map[string]any{"ecosystem": "Go", "name": "example.com/m", "version": "1.2.0"},
				"base_version":   "1.1.0",
				"target_version": "1.2.0",
				"change_kind":    "upgraded",
			}},
			want: map[string]any{"change": map[string]any{
				"package":        map[string]any{"ecosystem": "go", "name": "example.com/m", "version": "v1.2.0"},
				"base_version":   "v1.1.0",
				"target_version": "v1.2.0",
				"change_kind":    "upgraded",
			}},
		},
		{
			name: "flat container change normalizes its own versions",
			payload: map[string]any{"change": map[string]any{
				"ecosystem":      "Debian:12",
				"name":           "openssl",
				"base_version":   "1.1.1k",
				"target_version": "1.1.1w",
			}},
			want: map[string]any{"change": map[string]any{
				"ecosystem":      "debian:12",
				"name":           "openssl",
				"base_version":   "1.1.1k",
				"target_version": "1.1.1w",
			}},
		},
		{
			name: "nested vulnerability package normalizes",
			payload: map[string]any{"vulnerability": map[string]any{
				"package": map[string]any{"ecosystem": "Go", "name": "example.com/m", "version": "1.0.0"},
			}},
			want: map[string]any{"vulnerability": map[string]any{
				"package": map[string]any{"ecosystem": "go", "name": "example.com/m", "version": "v1.0.0"},
			}},
		},
		{
			name:    "fixed versions normalize",
			payload: map[string]any{"step": map[string]any{"ecosystem": "go", "fixed_version": "1.3.0", "fixed_versions": []any{"1.3.0", "1.4.0"}}},
			want:    map[string]any{"step": map[string]any{"ecosystem": "go", "fixed_version": "v1.3.0", "fixed_versions": []any{"v1.3.0", "v1.4.0"}}},
		},
		{
			name:    "unknown version sentinel survives",
			payload: map[string]any{"request": map[string]any{"ecosystem": "go", "name": "example.com/m", "version": UnknownVersion, "has_version": false}},
			want:    map[string]any{"request": map[string]any{"ecosystem": "go", "name": "example.com/m", "version": UnknownVersion, "has_version": false}},
		},
		{
			name:    "docker tags are left alone",
			payload: map[string]any{"pkg": map[string]any{"ecosystem": "docker", "name": "alpine", "version": "3.19"}},
			want:    map[string]any{"pkg": map[string]any{"ecosystem": "docker", "name": "alpine", "version": "3.19"}},
		},
		{
			name:    "object without an ecosystem keeps its version",
			payload: map[string]any{"sbom": map[string]any{"name": "report", "version": "1.5"}},
			want:    map[string]any{"sbom": map[string]any{"name": "report", "version": "1.5"}},
		},
		{
			name:    "package sibling without change versions does not leak normalization",
			payload: map[string]any{"pkg": map[string]any{"ecosystem": "go", "version": "1.0.0"}, "version": "2.0.0"},
			want:    map[string]any{"pkg": map[string]any{"ecosystem": "go", "version": "v1.0.0"}, "version": "2.0.0"},
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

// TestCanonicalizeLeavesCallerDataAlone pins that canonicalization stays on
// schema-defined ecosystem paths. Caller-supplied data that happens to use the
// key "ecosystem" is somebody's value, not an ecosystem, and an authorization
// rule comparing it exactly must still match.
func TestCanonicalizeLeavesCallerDataAlone(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
		want    map[string]any
	}{
		{
			name: "jwt claim survives",
			payload: map[string]any{
				"jwt": map[string]any{"sub": "svc", "ecosystem": "Customer_Success"},
				"pkg": map[string]any{"ecosystem": "Go"},
			},
			want: map[string]any{
				"jwt": map[string]any{"sub": "svc", "ecosystem": "Customer_Success"},
				"pkg": map[string]any{"ecosystem": "go"},
			},
		},
		{
			name: "jwt custom claim survives",
			payload: map[string]any{
				"jwt": map[string]any{"custom_claims": map[string]any{"ecosystem": "Customer_Success"}},
			},
			want: map[string]any{
				"jwt": map[string]any{"custom_claims": map[string]any{"ecosystem": "Customer_Success"}},
			},
		},
		{
			name: "container labels survive",
			payload: map[string]any{
				"image_info": map[string]any{"labels": map[string]any{"ecosystem": "Customer_Success"}},
			},
			want: map[string]any{
				"image_info": map[string]any{"labels": map[string]any{"ecosystem": "Customer_Success"}},
			},
		},
		{
			name:    "environment is left alone",
			payload: map[string]any{"env": map[string]any{"command": "scan", "ecosystem": "Customer_Success"}},
			want:    map[string]any{"env": map[string]any{"command": "scan", "ecosystem": "Customer_Success"}},
		},
		{
			name:    "untyped report payloads still canonicalize",
			payload: map[string]any{"report": map[string]any{"packages": []any{map[string]any{"ecosystem": "Go"}}}},
			want:    map[string]any{"report": map[string]any{"packages": []any{map[string]any{"ecosystem": "go"}}}},
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

// TestVariableCarriesEcosystem pins the schema gate that keeps the walk off
// caller-controlled variables, derived from proto descriptors rather than a
// hand-written list.
func TestVariableCarriesEcosystem(t *testing.T) {
	tests := []struct {
		variable string
		want     bool
	}{
		{variable: "pkg", want: true},
		{variable: "packages", want: true},
		{variable: "vulnerability", want: true},
		{variable: "node", want: true},
		{variable: "jwt", want: false},
		{variable: "env", want: false},
		{variable: "report", want: true},   // untyped payload, walked
		{variable: "request", want: true},  // untyped payload, walked
		{variable: "made_up", want: true},  // unknown variable, walked
		{variable: "licenses", want: true}, // untyped list, walked
	}

	for _, tt := range tests {
		t.Run(tt.variable, func(t *testing.T) {
			if got := variableCarriesEcosystem(tt.variable); got != tt.want {
				t.Errorf("variableCarriesEcosystem(%q) = %t, want %t", tt.variable, got, tt.want)
			}
		})
	}
}

// TestJWTClaimRuleStillMatches drives the flatten-then-canonicalize order the
// engine uses and pins that an exact-match authorization rule on a JWT claim
// keeps firing.
func TestJWTClaimRuleStillMatches(t *testing.T) {
	sources, err := ParseStructuredSources([]byte(`policies:
  - name: jwt-claim-gate
    rules:
      - action: deny
        when: jwt.ecosystem == "Customer_Success"
        reason: claim not allowed
`), "jwt.yaml")
	if err != nil {
		t.Fatalf("ParseStructuredSources: %v", err)
	}

	payload := map[string]any{
		"jwt": map[string]any{
			"sub":           "svc",
			"custom_claims": map[string]any{"ecosystem": "Customer_Success"},
		},
	}
	flattenJWTCustomClaims(payload)

	actions, err := EvaluateMap(t.Context(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateMap: %v", err)
	}
	if len(actions) != 1 || actions[0].Type != ActionDeny {
		t.Fatalf("jwt claim rule did not fire: actions=%v, jwt=%v", actions, payload["jwt"])
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
