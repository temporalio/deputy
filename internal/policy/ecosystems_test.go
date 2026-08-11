package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	"github.com/temporalio/deputy/internal/proto/descriptorset"
	"github.com/temporalio/deputy/internal/purlx"
	"google.golang.org/protobuf/reflect/protoreflect"
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
			// Counts reach the payload as int64 (protojson emits the declared
			// int32 as a JSON number, convertJSONNumbers makes it int64), so a
			// merged count has to stay an int64 or the policy sees a double.
			name:    "stats count map merges colliding spellings",
			payload: map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"Go": int64(2), "go": int64(3)}}},
			want:    map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"go": int64(5)}}},
		},
		{
			name:    "float counts stay floats",
			payload: map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"Go": 2.5, "go": 3.0}}},
			want:    map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"go": 5.5}}},
		},
		{
			name:    "json numbers merge",
			payload: map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"Go": json.Number("2"), "golang": json.Number("1")}}},
			want:    map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"go": int64(3)}}},
		},
		{
			name:    "fractional json numbers merge as floats",
			payload: map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"Go": json.Number("2.5"), "golang": json.Number("1")}}},
			want:    map[string]any{"stats": map[string]any{"ecosystems": map[string]any{"go": 3.5}}},
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
			name:    "go development-build sentinel survives",
			payload: map[string]any{"pkg": map[string]any{"ecosystem": "Go", "name": "k8s.io/ingress-nginx", "version": "(devel)"}},
			want:    map[string]any{"pkg": map[string]any{"ecosystem": "go", "name": "k8s.io/ingress-nginx", "version": "(devel)"}},
		},
		{
			// The purl library folds a pypi name halfway (lowercase and "_" to
			// "-"), so a dotted distribution is where the rewrite still has
			// work to do and where name and purl would otherwise disagree.
			name: "pypi purl name folds with the package name",
			payload: map[string]any{"pkg": map[string]any{
				"ecosystem": "PyPI", "name": "zope.interface", "version": "6.4",
				"purl": "pkg:pypi/zope.interface@6.4",
			}},
			want: map[string]any{"pkg": map[string]any{
				"ecosystem": "pypi", "name": "zope-interface", "version": "6.4",
				"purl": "pkg:pypi/zope-interface@6.4",
			}},
		},
		{
			// A crate is published, declared, and indexed with the hyphen it
			// was registered under, and the purl spec defines no normalization
			// for the cargo type, so neither the name nor the purl is rewritten.
			name: "cargo name and purl keep the published spelling",
			payload: map[string]any{"pkg": map[string]any{
				"ecosystem": "crates.io", "name": "async-trait", "version": "0.1.80",
				"purl": "pkg:cargo/async-trait@0.1.80",
			}},
			want: map[string]any{"pkg": map[string]any{
				"ecosystem": "cargo", "name": "async-trait", "version": "0.1.80",
				"purl": "pkg:cargo/async-trait@0.1.80",
			}},
		},
		{
			name: "go purl version gains the v prefix with the package version",
			payload: map[string]any{"pkg": map[string]any{
				"ecosystem": "Go", "name": "github.com/aws/aws-sdk-go", "version": "1.44.0",
				"purl": "pkg:golang/github.com/aws/aws-sdk-go@1.44.0",
			}},
			want: map[string]any{"pkg": map[string]any{
				"ecosystem": "go", "name": "github.com/aws/aws-sdk-go", "version": "v1.44.0",
				"purl": "pkg:golang/github.com/aws/aws-sdk-go@v1.44.0",
			}},
		},
		{
			name: "purl qualifiers and subpath survive the rewrite",
			payload: map[string]any{"pkg": map[string]any{
				"ecosystem": "Go", "name": "github.com/foo/bar", "version": "1.0.0",
				"purl": "pkg:golang/github.com/foo/bar@1.0.0?repository_url=proxy.golang.org#subpkg",
			}},
			want: map[string]any{"pkg": map[string]any{
				"ecosystem": "go", "name": "github.com/foo/bar", "version": "v1.0.0",
				"purl": "pkg:golang/github.com/foo/bar@v1.0.0?repository_url=proxy.golang.org#subpkg",
			}},
		},
		{
			// The name still folds, which is what shows the purl was skipped
			// for its type rather than skipped altogether.
			name: "purl of another type than the ecosystem is left alone",
			payload: map[string]any{"pkg": map[string]any{
				"ecosystem": "PyPI", "name": "Flask_SQLAlchemy",
				"purl": "pkg:github/Acme/Flask_SQLAlchemy@v1",
			}},
			want: map[string]any{"pkg": map[string]any{
				"ecosystem": "pypi", "name": "flask-sqlalchemy",
				"purl": "pkg:github/Acme/Flask_SQLAlchemy@v1",
			}},
		},
		{
			name: "unparseable purl is left alone",
			payload: map[string]any{"pkg": map[string]any{
				"ecosystem": "PyPI", "name": "Flask_SQLAlchemy", "purl": "not a purl",
			}},
			want: map[string]any{"pkg": map[string]any{
				"ecosystem": "pypi", "name": "flask-sqlalchemy", "purl": "not a purl",
			}},
		},
		{
			name: "npm purl needs no folding and keeps its scope encoding",
			payload: map[string]any{"pkg": map[string]any{
				"ecosystem": "npm", "name": "@types/node", "version": "20.0.0",
				"purl": "pkg:npm/%40types/node@20.0.0",
			}},
			want: map[string]any{"pkg": map[string]any{
				"ecosystem": "npm", "name": "@types/node", "version": "20.0.0",
				"purl": "pkg:npm/%40types/node@20.0.0",
			}},
		},
		{
			name: "advisory fixed versions inherit the finding's package ecosystem",
			payload: map[string]any{"vulnerability": map[string]any{
				"advisory_id": "GHSA-x",
				"package":     map[string]any{"ecosystem": "Go", "name": "example.com/m", "version": "1.0.0"},
				"advisory": map[string]any{
					"id":             "GHSA-x",
					"fixed_versions": []any{"1.2.0"},
					"resolved_fix":   map[string]any{"version": "1.2.0"},
					"package_fixes":  []any{map[string]any{"ecosystem": "Go", "module": "example.com/m/v2", "fixed_versions": []any{"2.0.1"}}},
				},
			}},
			want: map[string]any{"vulnerability": map[string]any{
				"advisory_id": "GHSA-x",
				"package":     map[string]any{"ecosystem": "go", "name": "example.com/m", "version": "v1.0.0"},
				"advisory": map[string]any{
					"id":             "GHSA-x",
					"fixed_versions": []any{"v1.2.0"},
					"resolved_fix":   map[string]any{"version": "v1.2.0"},
					"package_fixes":  []any{map[string]any{"ecosystem": "go", "module": "example.com/m/v2", "fixed_versions": []any{"v2.0.1"}}},
				},
			}},
		},
		{
			name:    "proxy request package name is normalized",
			payload: map[string]any{"request": map[string]any{"ecosystem": "PyPI", "package": "Flask-SQLAlchemy", "version": "3.1.1"}},
			want:    map[string]any{"request": map[string]any{"ecosystem": "pypi", "package": "flask-sqlalchemy", "version": "3.1.1"}},
		},
		{
			name:    "proxy request module is normalized",
			payload: map[string]any{"request": map[string]any{"ecosystem": "Go", "module": "example.com/M", "version": "1.0.0"}},
			want:    map[string]any{"request": map[string]any{"ecosystem": "go", "module": "example.com/M", "version": "v1.0.0"}},
		},
		{
			name: "container vulnerability change package name is normalized",
			payload: map[string]any{"vulnerability_change": map[string]any{
				"id": "CVE-1", "ecosystem": "PyPI", "package_name": "Flask-SQLAlchemy", "base_version": "3.1.1",
			}},
			want: map[string]any{"vulnerability_change": map[string]any{
				"id": "CVE-1", "ecosystem": "pypi", "package_name": "flask-sqlalchemy", "base_version": "3.1.1",
			}},
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
			name: "advisory source metadata survives",
			payload: map[string]any{"vulnerability": map[string]any{
				"package": map[string]any{"ecosystem": "Go", "version": "1.0.0"},
				"advisory": map[string]any{
					"database_specific": map[string]any{"version": "1.2.0", "ecosystem": "Customer_Success"},
				},
			}},
			want: map[string]any{"vulnerability": map[string]any{
				"package": map[string]any{"ecosystem": "go", "version": "v1.0.0"},
				"advisory": map[string]any{
					"database_specific": map[string]any{"version": "1.2.0", "ecosystem": "Customer_Success"},
				},
			}},
		},
		{
			name: "target provenance survives",
			payload: map[string]any{"node": map[string]any{
				"ecosystem":  "Go",
				"version":    "1.0.0",
				"provenance": map[string]any{"version": "1.0.0", "ecosystem": "Customer_Success"},
			}},
			want: map[string]any{"node": map[string]any{
				"ecosystem":  "go",
				"version":    "v1.0.0",
				"provenance": map[string]any{"version": "1.0.0", "ecosystem": "Customer_Success"},
			}},
		},
		{
			name: "a free-form entry named purl survives",
			payload: map[string]any{"node": map[string]any{
				"ecosystem":  "PyPI",
				"purl":       "pkg:pypi/zope.interface@6.4",
				"provenance": map[string]any{"purl": "pkg:pypi/zope.interface@6.4"},
			}},
			want: map[string]any{"node": map[string]any{
				"ecosystem":  "pypi",
				"purl":       "pkg:pypi/zope-interface@6.4",
				"provenance": map[string]any{"purl": "pkg:pypi/zope.interface@6.4"},
			}},
		},
		{
			name: "jwt claims named like a package identity survive",
			payload: map[string]any{
				"jwt": map[string]any{"ecosystem": "PyPI", "package": "Flask-SQLAlchemy", "version": "1.0.0"},
			},
			want: map[string]any{
				"jwt": map[string]any{"ecosystem": "PyPI", "package": "Flask-SQLAlchemy", "version": "1.0.0"},
			},
		},
		{
			name: "image labels named like a package identity survive",
			payload: map[string]any{
				"image_info": map[string]any{
					"ecosystem": "PyPI",
					"labels":    map[string]any{"package": "Flask-SQLAlchemy", "module": "Example.COM/M"},
				},
			},
			want: map[string]any{
				"image_info": map[string]any{
					"ecosystem": "pypi",
					"labels":    map[string]any{"package": "Flask-SQLAlchemy", "module": "Example.COM/M"},
				},
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

// TestEcosystemCountsStayIntegersInCEL pins the numeric type a policy sees for
// a graph stats count, which deputy.policy.v1.GraphStats declares as
// map<string, int32>. Merging a display spelling into its canonical one must
// not turn the count into a double: the bug only surfaces when aliases actually
// collide, so a stats map without a collision keeps working while an otherwise
// identical one with a collision breaks integer arithmetic. Both the CEL-level
// type and an int-only expression are asserted, since a double count still
// compares equal to the right number.
func TestEcosystemCountsStayIntegersInCEL(t *testing.T) {
	tests := []struct {
		name      string
		counts    map[string]int32
		wantCount int64
	}{
		{
			name:      "no alias collision",
			counts:    map[string]int32{"Go": 2, "npm": 1},
			wantCount: 2,
		},
		{
			name:      "display and canonical spelling collide",
			counts:    map[string]int32{"Go": 2, "go": 3},
			wantCount: 5,
		},
		{
			name:      "alias and display spelling collide",
			counts:    map[string]int32{"Go": 2, "golang": 4},
			wantCount: 6,
		},
		{
			name:      "three spellings collide",
			counts:    map[string]int32{"Go": 1, "go": 2, "golang": 4},
			wantCount: 7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stats, err := ProtoToMap(&policyv1.GraphStats{Ecosystems: tt.counts})
			if err != nil {
				t.Fatalf("ProtoToMap: %v", err)
			}

			isInt, err := Evaluate(t.Context(), `type(stats.ecosystems["go"]) == int`, map[string]any{"stats": stats})
			if err != nil {
				t.Fatalf("evaluate type check: %v", err)
			}
			if isInt != true {
				t.Errorf(`type(stats.ecosystems["go"]) is not int (counts=%v)`, tt.counts)
			}

			// Integer arithmetic has no double/int overload, so a count that
			// silently became a double fails to evaluate at all.
			sum, err := Evaluate(t.Context(), `stats.ecosystems["go"] + 1`, map[string]any{"stats": stats})
			if err != nil {
				t.Fatalf(`evaluate stats.ecosystems["go"] + 1 (counts=%v): %v`, tt.counts, err)
			}
			if sum != tt.wantCount+1 {
				t.Errorf(`stats.ecosystems["go"] + 1 = %#v, want %#v`, sum, tt.wantCount+1)
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

// TestValidateEcosystemsAcceptsScalibrEcosystems pins that a policy can scope
// itself to the ecosystems Deputy inventories through OSV-SCALIBR. Rejecting
// them would make the ecosystems: key unusable for Haskell, R, and C++ scans
// that the --ecosystems filter already supports.
func TestValidateEcosystemsAcceptsScalibrEcosystems(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "scanner spellings", in: []string{"Hackage", "CRAN", "ConanCenter"}, want: []string{"hackage", "cran", "conancenter"}},
		{name: "filter spellings", in: []string{"haskell", "r", "cpp"}, want: []string{"hackage", "cran", "conancenter"}},
		{name: "tool spellings", in: []string{"cabal", "renv", "conan"}, want: []string{"hackage", "cran", "conancenter"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateEcosystems(tt.in)
			if err != nil {
				t.Fatalf("validateEcosystems(%v): %v", tt.in, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("validateEcosystems(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestScalibrEcosystemGuardMatchesScannerSpelling closes the loop for those
// ecosystems: the guard a bundle generates from ecosystems: ["haskell"] has to
// match a package whose scanner-reported ecosystem is "Hackage".
func TestScalibrEcosystemGuardMatchesScannerSpelling(t *testing.T) {
	sources, err := ParseStructuredSources([]byte(`policies:
  - name: haskell-scoped
    ecosystems: ["haskell"]
    rules:
      - action: deny
        when: pkg.name != ""
        reason: matched
`), "haskell.yaml")
	if err != nil {
		t.Fatalf("ParseStructuredSources: %v", err)
	}

	payload := map[string]any{"pkg": map[string]any{"name": "aeson", "ecosystem": "Hackage", "version": "2.2.1"}}
	actions, err := EvaluateMap(t.Context(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateMap: %v", err)
	}
	if len(actions) != 1 || actions[0].Type != ActionDeny {
		t.Fatalf(`ecosystems: ["haskell"] did not match a "Hackage" package: actions=%v`, actions)
	}
}

// notPackageIdentity records, with a reason, the string fields that sit on a
// message declaring an ecosystem but are not part of a package's identity.
// TestIdentityKeysCoverSchema requires every such field to be listed here or in
// one of the identity key sets, so a schema that grows a new spelling of "the
// package name" fails the build instead of silently reaching policies
// unnormalized, which is how request.package and package_name were missed.
var notPackageIdentity = map[string]string{
	"advisory":      "an advisory identifier attributed to a subject, not a package name",
	"ecosystem":     "the ecosystem itself, canonicalized before the identity fields",
	"id":            "an advisory identifier",
	"aliases":       "advisory identifiers",
	"artifact":      "an advisory coverage subject, not a resolved package",
	"change_kind":   "an enum rendered as a string",
	"change_type":   "an enum rendered as a string",
	"description":   "prose",
	"display_name":  "an extractor's human-readable name",
	"file_patterns": "extractor file globs",
	"import_status": "an enum rendered as a string",
	"licenses":      "SPDX expressions",
	"locations":     "manifest paths",
	"operation":     "the proxy operation being requested",
	"published":     "a timestamp",
	"severity":      "a severity label",
	"severity_type": "a severity scoring system",
	"sources":       "advisory source names",
	"summary":       "prose",
	"target":        "what was scanned, not a package",
}

// TestIdentityKeysCoverSchema derives the check from the proto descriptors:
// every string field on a message that declares an ecosystem must be classified
// as a package name, a package version, a package URL, or explicitly not part
// of a package identity. The descriptor set covers all of Deputy's protos, not
// just the ones linked into this test binary, so a new field cannot hide in an
// unimported package.
func TestIdentityKeysCoverSchema(t *testing.T) {
	versionKeys := append(slices.Clone(packageVersionKeys), "fixed_versions")

	err := descriptorset.RangeMessages(func(md protoreflect.MessageDescriptor) bool {
		fields := md.Fields()
		declaresEcosystem := false
		for i := range fields.Len() {
			f := fields.Get(i)
			if string(f.Name()) == "ecosystem" && f.Kind() == protoreflect.StringKind && !f.IsList() {
				declaresEcosystem = true
				break
			}
		}
		if !declaresEcosystem {
			return true
		}
		t.Run(string(md.FullName()), func(t *testing.T) {
			for i := range fields.Len() {
				f := fields.Get(i)
				if f.Kind() != protoreflect.StringKind || f.IsMap() {
					continue
				}
				name := string(f.Name())
				if slices.Contains(packageNameKeys, name) || slices.Contains(versionKeys, name) || slices.Contains(packagePURLKeys, name) {
					continue
				}
				if _, known := notPackageIdentity[name]; known {
					continue
				}
				t.Errorf("%s.%s is a string field on a message that declares an ecosystem but is not classified: add it to packageNameKeys, packageVersionKeys, or packagePURLKeys if it holds a package identity, or to notPackageIdentity with the reason it does not", md.FullName(), name)
			}
		})
		return true
	})
	if err != nil {
		t.Fatalf("RangeMessages: %v", err)
	}
}

// TestPayloadNamesCollapseEquivalentSpellings pins the name half of the
// canonical identity contract: two payloads that name the same package in
// different but equivalent spellings must reach a policy as the same string.
// Lowercasing alone left "Flask_SQLAlchemy" and "flask.sqlalchemy" as distinct
// identities, so an exact-match rule matched one spelling and missed the other
// even though inventory comparison treats them as one package.
func TestPayloadNamesCollapseEquivalentSpellings(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		spellings []string
		want      string
	}{
		{
			name:      "pypi separators and case",
			ecosystem: "PyPI",
			spellings: []string{"Flask_SQLAlchemy", "flask.sqlalchemy", "Flask-SQLAlchemy", "flask-sqlalchemy"},
			want:      "flask-sqlalchemy",
		},
		{
			// crates.io folds "-" and "_" to resolve a crate, but it publishes
			// the crate under the spelling it was registered with, so identity
			// is what a policy reads and the fold stays at the comparison.
			name:      "cargo crate keeps its published spelling",
			ecosystem: "crates.io",
			spellings: []string{"async-trait"},
			want:      "async-trait",
		},
		{
			name:      "npm names stay verbatim",
			ecosystem: "npm",
			spellings: []string{"@types/Node"},
			want:      "@types/Node",
		},
		{
			name:      "go module paths stay verbatim",
			ecosystem: "Go",
			spellings: []string{"github.com/Masterminds/semver"},
			want:      "github.com/Masterminds/semver",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, spelling := range tt.spellings {
				payload := map[string]any{
					"pkg": map[string]any{"ecosystem": tt.ecosystem, "name": spelling},
				}
				canonicalizeEcosystemPayload(payload)
				pkg, ok := payload["pkg"].(map[string]any)
				if !ok {
					t.Fatalf("pkg is %T, want map", payload["pkg"])
				}
				if got := pkg["name"]; got != tt.want {
					t.Errorf("name %q canonicalized to %v, want %q", spelling, got, tt.want)
				}
			}
		})
	}
}

// TestPURLAgreesWithIdentityFields pins the invariant the PURL rewrite exists
// for: after canonicalization, the package a policy reads through
// purl(pkg.purl) is the package it reads through pkg.name and pkg.version. The
// PURL is parsed with the same library the purl() CEL helper uses, and its
// namespace is rejoined with its name because a PURL splits an identity that
// the name field carries whole (pkg:golang/github.com/aws + aws-sdk-go).
// Before the rewrite, a Cargo PURL kept the unfolded "serde-json" and a Go PURL
// kept an unprefixed version, so an exact-match rule matched or missed
// depending only on which representation it read.
func TestPURLAgreesWithIdentityFields(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		pkgName   string
		version   string
		purl      string
	}{
		{
			name:      "cargo name and purl keep their hyphen together",
			ecosystem: "crates.io",
			pkgName:   "async-trait",
			version:   "0.1.80",
			purl:      "pkg:cargo/async-trait@0.1.80",
		},
		{
			name:      "go version gains its prefix",
			ecosystem: "Go",
			pkgName:   "github.com/aws/aws-sdk-go",
			version:   "1.44.0",
			purl:      "pkg:golang/github.com/aws/aws-sdk-go@1.44.0",
		},
		{
			name:      "pypi name folds",
			ecosystem: "PyPI",
			pkgName:   "Flask_SQLAlchemy",
			version:   "3.1.1",
			purl:      "pkg:pypi/Flask_SQLAlchemy@3.1.1",
		},
		{
			// The purl library does not collapse a dot, so this is the pypi
			// spelling where only Deputy's own fold makes the two agree.
			name:      "dotted pypi name folds",
			ecosystem: "PyPI",
			pkgName:   "zope.interface",
			version:   "6.4",
			purl:      "pkg:pypi/zope.interface@6.4",
		},
		{
			name:      "npm scope survives",
			ecosystem: "npm",
			pkgName:   "@types/node",
			version:   "20.0.0",
			purl:      "pkg:npm/%40types/node@20.0.0",
		},
		{
			name:      "maven coordinates survive",
			ecosystem: "Maven",
			pkgName:   "org.apache/commons",
			version:   "1.0",
			purl:      "pkg:maven/org.apache/commons@1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]any{"pkg": map[string]any{
				"ecosystem": tt.ecosystem,
				"name":      tt.pkgName,
				"version":   tt.version,
				"purl":      tt.purl,
			}}
			canonicalizeEcosystemPayload(payload)
			pkg, ok := payload["pkg"].(map[string]any)
			if !ok {
				t.Fatalf("pkg is %T, want map", payload["pkg"])
			}
			parsed, err := purlx.ParseLoose(pkg["purl"].(string))
			if err != nil {
				t.Fatalf("canonicalized purl %q no longer parses: %v", pkg["purl"], err)
			}
			purlName := parsed.Name
			if parsed.Namespace != "" {
				purlName = parsed.Namespace + "/" + parsed.Name
			}
			if want := pkg["name"]; purlName != want && "@"+purlName != want {
				t.Errorf("purl names %q but the package names %q", purlName, want)
			}
			if want := pkg["version"]; parsed.Version != want {
				t.Errorf("purl version %q, package version %q", parsed.Version, want)
			}
		})
	}
}

// TestPURLStringSpellsTheCanonicalName pins the purl as a policy reads it,
// which is a string, rather than as it re-parses. The two differ: the purl
// library folds a pypi name on its own at parse time, so comparing parsed
// components let "pkg:pypi/Flask_SQLAlchemy@3.1.1" sit beside the name
// "flask-sqlalchemy" and call it agreement. A rule doing string equality on
// pkg.purl saw the spelling nothing else in the payload used.
//
// The cases the rewrite must not touch are pinned here too, because the
// rewrite is the risk: the purl library lowercases a golang namespace at parse,
// and Go import paths are case-sensitive, so re-encoding a purl whose
// components Deputy does not fold would trade this bug for the same bug in
// another ecosystem.
func TestPURLStringSpellsTheCanonicalName(t *testing.T) {
	tests := []struct {
		name      string
		ecosystem string
		pkgName   string
		version   string
		purl      string
		wantName  string
		wantPURL  string
	}{
		{
			name:      "underscored pypi name reaches the purl string",
			ecosystem: "PyPI",
			pkgName:   "Flask_SQLAlchemy",
			version:   "3.1.1",
			purl:      "pkg:pypi/Flask_SQLAlchemy@3.1.1",
			wantName:  "flask-sqlalchemy",
			wantPURL:  "pkg:pypi/flask-sqlalchemy@3.1.1",
		},
		{
			name:      "dotted pypi name reaches the purl string",
			ecosystem: "PyPI",
			pkgName:   "flask.sqlalchemy",
			version:   "3.1.1",
			purl:      "pkg:pypi/flask.sqlalchemy@3.1.1",
			wantName:  "flask-sqlalchemy",
			wantPURL:  "pkg:pypi/flask-sqlalchemy@3.1.1",
		},
		{
			name:      "pypi qualifiers survive the rewrite",
			ecosystem: "PyPI",
			pkgName:   "Flask_SQLAlchemy",
			version:   "3.1.1",
			purl:      "pkg:pypi/Flask_SQLAlchemy@3.1.1?file_name=x.whl",
			wantName:  "flask-sqlalchemy",
			wantPURL:  "pkg:pypi/flask-sqlalchemy@3.1.1?file_name=x.whl",
		},
		{
			name:      "cargo keeps the published spelling",
			ecosystem: "crates.io",
			pkgName:   "async-trait",
			version:   "0.1.80",
			purl:      "pkg:cargo/async-trait@0.1.80",
			wantName:  "async-trait",
			wantPURL:  "pkg:cargo/async-trait@0.1.80",
		},
		{
			name:      "go version gains its prefix in the string",
			ecosystem: "Go",
			pkgName:   "github.com/aws/aws-sdk-go",
			version:   "1.44.0",
			purl:      "pkg:golang/github.com/aws/aws-sdk-go@1.44.0",
			wantName:  "github.com/aws/aws-sdk-go",
			wantPURL:  "pkg:golang/github.com/aws/aws-sdk-go@v1.44.0",
		},
		{
			name:      "case-sensitive go namespace survives",
			ecosystem: "Go",
			pkgName:   "github.com/Masterminds/semver",
			version:   "v1.0.0",
			purl:      "pkg:golang/github.com/Masterminds/semver@v1.0.0",
			wantName:  "github.com/Masterminds/semver",
			wantPURL:  "pkg:golang/github.com/Masterminds/semver@v1.0.0",
		},
		{
			// When a Go PURL is rewritten it comes back with the namespace the
			// purl spec mandates for the golang type, which is lowercase, so
			// the string cannot carry a case-sensitive import path and be a
			// canonical PURL at the same time. Re-parsing either spelling
			// yields this same package, which is the agreement
			// [TestPURLAgreesWithIdentityFields] checks; the case above pins
			// that a PURL needing no rewrite is not put through this at all.
			name:      "rewritten go purl takes the spec's namespace casing",
			ecosystem: "Go",
			pkgName:   "github.com/Masterminds/semver",
			version:   "1.0.0",
			purl:      "pkg:golang/github.com/Masterminds/semver@1.0.0",
			wantName:  "github.com/Masterminds/semver",
			wantPURL:  "pkg:golang/github.com/masterminds/semver@v1.0.0",
		},
		{
			name:      "go qualifiers and subpath survive",
			ecosystem: "Go",
			pkgName:   "github.com/foo/bar",
			version:   "1.0.0",
			purl:      "pkg:golang/github.com/foo/bar@1.0.0?repository_url=proxy.golang.org#subpkg",
			wantName:  "github.com/foo/bar",
			wantPURL:  "pkg:golang/github.com/foo/bar@v1.0.0?repository_url=proxy.golang.org#subpkg",
		},
		{
			name:      "npm scope encoding survives",
			ecosystem: "npm",
			pkgName:   "@types/node",
			version:   "20.0.0",
			purl:      "pkg:npm/%40types/node@20.0.0",
			wantName:  "@types/node",
			wantPURL:  "pkg:npm/%40types/node@20.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]any{"pkg": map[string]any{
				"ecosystem": tt.ecosystem,
				"name":      tt.pkgName,
				"version":   tt.version,
				"purl":      tt.purl,
			}}
			canonicalizeEcosystemPayload(payload)
			pkg, ok := payload["pkg"].(map[string]any)
			if !ok {
				t.Fatalf("pkg is %T, want map", payload["pkg"])
			}
			if got := pkg["name"]; got != tt.wantName {
				t.Errorf("name = %v, want %q", got, tt.wantName)
			}
			if got := pkg["purl"]; got != tt.wantPURL {
				t.Errorf("purl = %v, want %q", got, tt.wantPURL)
			}
		})
	}
}

// policyInputsDoc is the reference whose payload samples document what a policy
// receives.
const policyInputsDoc = "../../docs/reference/policy-inputs.md"

// jsonSampleBlocks returns the fenced json blocks of a markdown file that parse
// as a JSON object. Blocks that do not parse are prose illustrations with
// elisions rather than payload samples, and blocks that are not objects are not
// payloads at all.
func jsonSampleBlocks(t *testing.T, path string) map[int]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	out := make(map[int]string)
	for i, block := range strings.Split(string(data), "```json") {
		if i == 0 {
			continue
		}
		body, _, found := strings.Cut(block, "```")
		if !found {
			continue
		}
		var probe map[string]any
		if json.Unmarshal([]byte(body), &probe) != nil {
			continue
		}
		out[i] = body
	}
	return out
}

// TestDocumentedPayloadsAreCanonical checks every payload sample in the policy
// input reference against the canonicalization a real payload goes through: a
// sample that changes is a sample showing a value no policy will ever see.
// Copying such a sample into an exact-match rule produces a rule that never
// fires, which is how the reference came to show a Go version without its "v"
// prefix while the text beside it promised the prefix.
func TestDocumentedPayloadsAreCanonical(t *testing.T) {
	samples := jsonSampleBlocks(t, policyInputsDoc)
	if len(samples) == 0 {
		t.Fatalf("no json payload samples found in %s", policyInputsDoc)
	}
	for i, body := range samples {
		t.Run(fmt.Sprintf("block-%d", i), func(t *testing.T) {
			var documented, canonical map[string]any
			if err := json.Unmarshal([]byte(body), &documented); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if err := json.Unmarshal([]byte(body), &canonical); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			canonicalizeEcosystemPayload(canonical)
			if !reflect.DeepEqual(documented, canonical) {
				t.Errorf("documented payload is not what a policy sees:\n documented: %#v\n canonical:  %#v", documented, canonical)
			}
		})
	}
}
