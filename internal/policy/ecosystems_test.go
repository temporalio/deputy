package policy

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	fixv1 "github.com/temporalio/deputy/gen/deputy/fix/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	"github.com/temporalio/deputy/internal/ecosystem"
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

// TestEveryProxyCapableEcosystemHasAnEntrypoint sweeps the registry rather than
// a list of ecosystems anyone maintains. ProxyEntrypoint answers "" for an
// ecosystem with no artifact-request entrypoint, and a handler for such an
// ecosystem is refused rather than served (see internal/proxy), so an ecosystem
// that declares proxy capability without an entrypoint to enforce policy at
// cannot be proxied at all. Deriving the cases from Capabilities().Proxy is what
// makes that a build-time answer instead of a discovery at request time.
func TestEveryProxyCapableEcosystemHasAnEntrypoint(t *testing.T) {
	proxyCapable := 0
	for _, eco := range ecosystem.All() {
		if !eco.Capabilities().Proxy {
			continue
		}
		proxyCapable++
		t.Run(string(eco), func(t *testing.T) {
			got := ProxyEntrypoint(string(eco))
			if got == "" {
				t.Fatalf("proxy-capable ecosystem %s has no artifact-request entrypoint, so a proxy for it cannot be served", eco)
			}
			if !got.IsValid() {
				t.Fatalf("ProxyEntrypoint(%q) = %q, which is not a canonical policy entrypoint", eco, got)
			}
			if want := Entrypoint(string(eco) + "_artifact_request"); got != want {
				t.Fatalf("ProxyEntrypoint(%q) = %q, want the synthesized %q", eco, got, want)
			}
		})
	}

	// Sanity floor: 4 proxy-capable ecosystems today (go, npm, pypi,
	// rubygems); zero would make every assertion above vacuous.
	if proxyCapable < 4 {
		t.Errorf("only %d proxy-capable ecosystems in ecosystem.All(), want at least 4", proxyCapable)
	}
}

// TestProxyEntrypoint pins the resolutions the sweep above cannot ask about:
// the spellings an ecosystem arrives under, and the answer for an ecosystem
// that has no artifact-request entrypoint at all.
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
		{
			// A remediation step names a manager, not an ecosystem, and holds no
			// nested package. Its package URL is the only thing in it that says
			// which ecosystem's rules apply.
			name: "a step resolves its ecosystem from its own package url",
			payload: map[string]any{"step": map[string]any{
				"manager": "go", "package": "example.com/m", "version": "1.2.3",
				"target_version": "1.3.0", "purl": "pkg:golang/example.com/m@1.2.3",
			}},
			want: map[string]any{"step": map[string]any{
				"manager": "go", "package": "example.com/m", "version": "v1.2.3",
				"target_version": "v1.3.0", "purl": "pkg:golang/example.com/m@v1.2.3",
			}},
		},
		{
			// The type has to be one a registration claims. Deputy has no
			// folding rules for anything else, and applying some other
			// ecosystem's would rewrite an identity it does not own.
			name: "a package url of an unclaimed type leaves the object unresolved",
			payload: map[string]any{"step": map[string]any{
				"package": "Thing", "version": "1.2.3", "purl": "pkg:acme-internal/Thing@1.2.3",
			}},
			want: map[string]any{"step": map[string]any{
				"package": "Thing", "version": "1.2.3", "purl": "pkg:acme-internal/Thing@1.2.3",
			}},
		},
		{
			// An object that declares an ecosystem is stating which rules apply
			// to it, so the declaration outranks the URL: a crate may carry a
			// pkg:github reference, and it stays a reference.
			name: "a declared ecosystem outranks the package url beside it",
			payload: map[string]any{"pkg": map[string]any{
				"ecosystem": "Cargo", "name": "async-trait", "version": "1.2.3",
				"purl": "pkg:github/actions/checkout@1.2.3",
			}},
			want: map[string]any{"pkg": map[string]any{
				"ecosystem": "cargo", "name": "async-trait", "version": "1.2.3",
				"purl": "pkg:github/actions/checkout@1.2.3",
			}},
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
	"added":                             "SPDX identifiers a license change added",
	"advisory":                          "an advisory identifier attributed to a subject, not a package name",
	"advisory_id":                       "an advisory identifier",
	"aliases":                           "advisory identifiers",
	"architecture":                      "an image platform architecture",
	"artifact":                          "an advisory coverage subject, not a resolved package",
	"author":                            "an image author",
	"category":                          "a risk factor category",
	"chain_id":                          "a container layer chain digest",
	"change_kind":                       "an enum rendered as a string",
	"change_type":                       "an enum rendered as a string",
	"cmd":                               "an image default command",
	"command":                           "the build instruction that produced a layer",
	"comment":                           "prose on an image history entry",
	"component_key":                     "the dependency key exactly as the manifest spells it, kept unfolded so remediation can edit that entry",
	"conflicts":                         "conflicting SPDX identifiers",
	"created_by":                        "the build instruction that created a layer",
	"cve":                               "an advisory identifier",
	"cwes":                              "weakness identifiers",
	"deprecation_message":               "prose from a registry deprecation notice",
	"description":                       "prose",
	"details":                           "prose",
	"diff_id":                           "a container layer content digest",
	"digest":                            "an image content digest",
	"display_name":                      "an extractor's human-readable name",
	"docker_version":                    "the builder's Docker version, not a package version",
	"ecosystem":                         "the ecosystem itself, canonicalized before the identity fields",
	"entrypoint":                        "an image entrypoint",
	"env":                               "image environment variables",
	"exposed_ports":                     "image port declarations",
	"file_patterns":                     "extractor file globs",
	"groups":                            "dependency groups such as dev or test",
	"id":                                "an advisory identifier",
	"image":                             "a container image reference",
	"import_status":                     "an enum rendered as a string",
	"indicators":                        "malware detection indicators",
	"kev_date_added":                    "a KEV catalog date",
	"kev_due_date":                      "a KEV compliance deadline",
	"kev_known_ransomware_campaign_use": "a KEV ransomware flag",
	"kev_required_action":               "prose from the KEV catalog",
	"kind":                              "an enum rendered as a string",
	"licenses":                          "SPDX expressions",
	"locations":                         "manifest paths",
	"manager":                           "the package manager that owns a manifest",
	"modified":                          "a timestamp",
	"on_build":                          "image ONBUILD triggers",
	"operation":                         "the proxy operation being requested",
	"os":                                "an image platform OS",
	"os_version":                        "an image platform OS version, not a package version",
	"path":                              "a file path, an import path, or a dependency chain; a chain of package URLs is canonicalized as references, not as one object's name",
	"published":                         "a timestamp",
	"raw":                               "a severity score as its source published it",
	"raw_type":                          "a severity scoring system",
	"references":                        "advisory reference URLs",
	"registry":                          "a container registry host",
	"remediation":                       "prose",
	"removed":                           "SPDX identifiers a license change removed",
	"repository":                        "a container image repository",
	"sensitive_env":                     "image environment variable names flagged as sensitive",
	"severity":                          "a severity label",
	"severity_type":                     "a severity scoring system",
	"shell":                             "an image default shell",
	"source":                            "the data source that produced a risk signal",
	"sources":                           "advisory source names",
	"spdx_ids":                          "SPDX license identifiers",
	"status":                            "an enum rendered as a string",
	"stop_signal":                       "an image stop signal",
	"summary":                           "prose",
	"symbols":                           "vulnerable symbol names",
	"tag":                               "a container image tag",
	"target":                            "what was scanned, not a package",
	"test":                              "an image healthcheck command",
	"user":                              "an image default user",
	"variant":                           "an image platform variant",
	"volumes":                           "image volume declarations",
	"working_dir":                       "an image working directory",
}

// declaresEcosystemField reports whether md has a singular string field named
// "ecosystem", which is what [canonicalizeOwnEcosystem] reads.
func declaresEcosystemField(md protoreflect.MessageDescriptor) bool {
	fields := md.Fields()
	for i := range fields.Len() {
		f := fields.Get(i)
		if string(f.Name()) == "ecosystem" && f.Kind() == protoreflect.StringKind && !f.IsList() {
			return true
		}
	}
	return false
}

// namesPackageThroughNestedField reports whether md resolves its ecosystem from
// a nested package message, mirroring [nestedPackageEcosystem]. A finding names
// no ecosystem of its own but normalizes its identity fields against the one
// its package declares, so its fields need the same classification.
func namesPackageThroughNestedField(md protoreflect.MessageDescriptor) bool {
	for _, key := range []string{"package", "pkg"} {
		f := md.Fields().ByName(protoreflect.Name(key))
		if f == nil || f.Kind() != protoreflect.MessageKind || f.IsList() || f.IsMap() {
			continue
		}
		if declaresEcosystemField(f.Message()) {
			return true
		}
	}
	return false
}

// arrivesAsItsOwnVariable reports whether a field name reaches policies as a
// top-level payload variable that [variableCarriesEcosystem] keeps out of the
// walk. A policy payload is flat: "env", "target", and "jwt" are siblings of
// "pkg", not children of it, and each is gated on its own before the walk
// starts. Following the proto nesting into them would demand a classification
// for fields no ecosystem ever reaches, which is how a coverage rule stops
// describing the code it guards.
func arrivesAsItsOwnVariable(name string) bool {
	if _, known := VariableInfo(name); !known {
		return false
	}
	return !variableCarriesEcosystem(name)
}

// identityCoverageMessages returns every message whose string fields the
// canonicalization walk can rewrite: one that declares an ecosystem, one that
// names its package through a nested message, and everything reachable from
// either. Reachability is the point of the derivation: an object with no
// ecosystem of its own inherits the enclosing one (see
// [canonicalizeEcosystemValue]), so a nested message's version field is
// normalized exactly like the ecosystem-declaring parent's. Seeding on the
// declaring message alone left those nested fields unclassified, which is how
// FixVerdict.claimed kept an unnormalized spelling of a version its sibling
// field normalized.
func identityCoverageMessages() map[protoreflect.FullName]protoreflect.MessageDescriptor {
	out := make(map[protoreflect.FullName]protoreflect.MessageDescriptor)
	var visit func(md protoreflect.MessageDescriptor)
	visit = func(md protoreflect.MessageDescriptor) {
		if md == nil || out[md.FullName()] != nil {
			return
		}
		out[md.FullName()] = md
		fields := md.Fields()
		for i := range fields.Len() {
			f := fields.Get(i)
			if f.IsMap() {
				// Scalar maps are free-form caller data the walk never
				// descends into; message-valued maps are not a shape Deputy's
				// policy inputs use.
				continue
			}
			if arrivesAsItsOwnVariable(string(f.Name())) {
				continue
			}
			if f.Kind() == protoreflect.MessageKind || f.Kind() == protoreflect.GroupKind {
				visit(f.Message())
			}
		}
	}
	_ = descriptorset.RangeMessages(func(md protoreflect.MessageDescriptor) bool {
		if declaresEcosystemField(md) || namesPackageThroughNestedField(md) {
			visit(md)
		}
		return true
	})
	return out
}

// TestIdentityKeysCoverSchema derives the check from the proto descriptors:
// every string field the canonicalization walk can reach with an ecosystem in
// hand must be classified as a package name, a package version, a package URL,
// or explicitly not part of a package identity. The descriptor set covers all
// of Deputy's protos, not just the ones linked into this test binary, so a new
// field cannot hide in an unimported package.
func TestIdentityKeysCoverSchema(t *testing.T) {
	versionKeys := append(slices.Clone(packageVersionKeys), "fixed_versions")

	messages := identityCoverageMessages()
	if len(messages) == 0 {
		t.Fatal("no messages reached the identity coverage walk")
	}
	for _, name := range slices.Sorted(maps.Keys(messages)) {
		md := messages[name]
		t.Run(string(name), func(t *testing.T) {
			fields := md.Fields()
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
				t.Errorf("%s.%s is a string field the canonicalization walk reaches with an ecosystem but is not classified: add it to packageNameKeys, packageVersionKeys, or packagePURLKeys if it holds a package identity, or to notPackageIdentity with the reason it does not", md.FullName(), name)
			}
		})
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

// TestGraphReferencesSpellTheNodeTheyName pins the graph identity contract: a
// node, the roots list, and both ends of every edge must spell one package one
// way. Only the node declares an ecosystem, so canonicalizing on that alone
// moved node.purl to "pkg:golang/example.com/mod@v1.2.3" and left roots and
// edge.to on the unprefixed spelling, which quietly made "node.purl in roots"
// and "edge.to == to_node.purl" false for every Go package.
//
// A finding's "path" is deliberately not among them. Deputy fills it with the
// node names along the chain (report.computeGraphPath), and the same key names a
// file path on every other message a policy reads, so it is not classified as a
// package reference and arrives as it was given. See
// [TestFilesystemPathsReachPolicyVerbatim].
func TestGraphReferencesSpellTheNodeTheyName(t *testing.T) {
	const (
		rawRoot  = "pkg:golang/example.com/root@1.0.0"
		rawDep   = "pkg:golang/example.com/mod@1.2.3"
		wantRoot = "pkg:golang/example.com/root@v1.0.0"
		wantDep  = "pkg:golang/example.com/mod@v1.2.3"
	)
	payload := map[string]any{
		"nodes": []any{
			map[string]any{"purl": rawRoot, "name": "example.com/root", "version": "1.0.0", "ecosystem": "Go"},
			map[string]any{"purl": rawDep, "name": "example.com/mod", "version": "1.2.3", "ecosystem": "Go"},
		},
		"edges":   []any{map[string]any{"from": rawRoot, "to": rawDep, "constraint": "^1.2.0"}},
		"roots":   []any{rawRoot},
		"node":    map[string]any{"purl": rawDep, "ecosystem": "Go", "version": "1.2.3"},
		"to_node": map[string]any{"purl": rawDep, "ecosystem": "Go", "version": "1.2.3"},
		"edge":    map[string]any{"from": rawRoot, "to": rawDep},
		"graph":   map[string]any{"roots": []any{rawRoot}},
		"vulnerability": map[string]any{
			"package": map[string]any{"ecosystem": "Go", "version": "1.2.3"},
			"path":    []any{rawRoot, rawDep},
		},
	}
	canonicalizeEcosystemPayload(payload)

	edge := payload["edge"].(map[string]any)
	reported := []struct {
		what string
		got  any
		want string
	}{
		{"nodes[0].purl", payload["nodes"].([]any)[0].(map[string]any)["purl"], wantRoot},
		{"nodes[1].purl", payload["nodes"].([]any)[1].(map[string]any)["purl"], wantDep},
		{"roots[0]", payload["roots"].([]any)[0], wantRoot},
		{"graph.roots[0]", payload["graph"].(map[string]any)["roots"].([]any)[0], wantRoot},
		{"edges[0].from", payload["edges"].([]any)[0].(map[string]any)["from"], wantRoot},
		{"edges[0].to", payload["edges"].([]any)[0].(map[string]any)["to"], wantDep},
		{"edges[0].constraint", payload["edges"].([]any)[0].(map[string]any)["constraint"], "^1.2.0"},
		{"edge.from", edge["from"], wantRoot},
		{"edge.to", edge["to"], wantDep},
		{"to_node.purl", payload["to_node"].(map[string]any)["purl"], wantDep},
		{"vulnerability.path[0]", payload["vulnerability"].(map[string]any)["path"].([]any)[0], rawRoot},
		{"vulnerability.path[1]", payload["vulnerability"].(map[string]any)["path"].([]any)[1], rawDep},
	}
	for _, r := range reported {
		if r.got != r.want {
			t.Errorf("%s = %v, want %q", r.what, r.got, r.want)
		}
	}
}

// TestFilesystemPathsReachPolicyVerbatim pins the guarantee a path rule depends
// on: the string a policy evaluates is the string Deputy was handed. Classifying
// the bare name "path" as a package reference broke it, because the walk sees the
// key without the message that declared it, and the descriptors give "path" a
// file path on every message a policy reads it from: a remediation step's
// manifest, a package's manifest refs, a scanned Dockerfile. Each of those was
// rewritten as soon as its value parsed as a package URL, so an exact-match rule
// on the requested path compared against a spelling Deputy invented, which is the
// same failure as the sandbox argv (TestExecutionPolicyReadsTheRequestedArgv).
//
// The values here are paths that also parse as package URLs, because that is the
// only case where the classification is load-bearing: the parser already leaves
// an ordinary path alone, and a rule is written against the values it accepts.
func TestFilesystemPathsReachPolicyVerbatim(t *testing.T) {
	const requested = "pkg:golang/example.com/mod@1.2.3"
	tests := []struct {
		name    string
		payload map[string]any
		read    func(map[string]any) any
	}{
		{
			name: "a remediation step's manifest path",
			payload: map[string]any{
				"step": &fixv1.RemediationCommand{
					Manager: "go",
					Command: "go get example.com/mod@v1.2.4",
					Path:    requested,
				},
			},
			read: func(p map[string]any) any { return p["step"].(map[string]any)["path"] },
		},
		{
			name: "a manifest ref on the package a policy reads",
			payload: map[string]any{
				"pkg": &dependencyv1.Package{
					Name:         "example.com/mod",
					Version:      "1.2.3",
					Ecosystem:    "Go",
					ManifestRefs: []*dependencyv1.ManifestRef{{Path: requested}},
				},
			},
			read: func(p map[string]any) any {
				refs := p["pkg"].(map[string]any)["manifest_refs"].([]any)
				return refs[0].(map[string]any)["path"]
			},
		},
		{
			// The Dockerfile payload is a hand-built map (dockerfile.Info.ToMap),
			// so no descriptor stands between the key and the rewrite either.
			name:    "the path of a scanned Dockerfile",
			payload: map[string]any{"dockerfile": map[string]any{"path": requested, "stages": []any{}}},
			read:    func(p map[string]any) any { return p["dockerfile"].(map[string]any)["path"] },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := convertProtosInMap(tt.payload)
			canonicalizeEcosystemPayload(payload)
			if got := tt.read(payload); got != requested {
				t.Errorf("path reached the policy as %v, want the requested %q", got, requested)
			}
		})
	}
}

// TestReferencesAndIdentityAgreeOnTheScheme pins the two passes to one answer
// about what a package URL is. A PURL scheme is case-insensitive and the parser
// accepts it that way, so "PKG:golang/..." is a package URL and Deputy's own
// leading-whitespace tolerance makes " pkg:golang/..." one too. The reference
// pass used to decide with a byte-exact "pkg:" prefix test, so an object's
// identity PURL was canonicalized while the same string in roots or on an edge
// came back untouched, and "node.purl in roots" was false for no reason but
// spelling.
func TestReferencesAndIdentityAgreeOnTheScheme(t *testing.T) {
	sources, err := ParseStructuredSources([]byte(`policies:
  - name: root-membership
    rules:
      - action: deny
        when: node.purl in roots && edge.to == node.purl
        reason: matched
`), "roots.yaml")
	if err != nil {
		t.Fatalf("ParseStructuredSources: %v", err)
	}

	tests := []struct {
		name string
		raw  string
	}{
		{name: "canonical scheme", raw: "pkg:golang/example.com/mod@1.2.3"},
		{name: "upper case scheme", raw: "PKG:golang/example.com/mod@1.2.3"},
		{name: "mixed case scheme", raw: "Pkg:golang/example.com/mod@1.2.3"},
		{name: "leading whitespace", raw: " pkg:golang/example.com/mod@1.2.3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := purlx.ParseLoose(tt.raw); err != nil {
				t.Fatalf("fixture precondition: ParseLoose(%q) = %v, want a package URL", tt.raw, err)
			}
			payload := map[string]any{
				"node":  map[string]any{"purl": tt.raw, "ecosystem": "Go", "version": "1.2.3"},
				"roots": []any{tt.raw},
				"edge":  map[string]any{"from": "pkg:golang/example.com/root@1.0.0", "to": tt.raw},
			}
			actions, err := EvaluateMap(t.Context(), sources, payload)
			if err != nil {
				t.Fatalf("EvaluateMap: %v", err)
			}
			if len(actions) != 1 || actions[0].Type != ActionDeny {
				node := payload["node"].(map[string]any)
				t.Fatalf("root membership rule did not fire for %q: actions=%v (node.purl=%v roots=%v edge.to=%v)",
					tt.raw, actions, node["purl"], payload["roots"], payload["edge"].(map[string]any)["to"])
			}
		})
	}
}

// TestHandBuiltVersionListsNormalize drives the map surface of the engine,
// EvaluateAllMap, which is what a caller reaches for when it assembles a payload
// itself rather than handing over a proto. A repeated version field arrives as
// []any from a proto and commonly as []string from such a caller, and only the
// first was normalized, so one payload carried both conventions: the scalar
// versions gained their "v" and the fixed versions beside them did not.
//
// The caller's slice is asserted unchanged in the same pass. The payload clone
// the engine makes is shallow, so writing into the slice a caller handed over
// would rewrite data it still owns, which is worse than the inconsistency.
func TestHandBuiltVersionListsNormalize(t *testing.T) {
	eng, err := NewEngine([]Source{{
		Name: "fixed-versions",
		Body: `vulnerability.advisory.fixed_versions.exists(v, v == "v1.44.1")
  ? [{"action": "deny", "reason": "matched"}]
  : [{"action": "allow"}]`,
	}})
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	tests := []struct {
		name  string
		build func() (fixed any, unchanged func() bool)
	}{
		{
			name: "a string slice",
			build: func() (any, func() bool) {
				fixed := []string{"1.44.1", "1.45.0"}
				return fixed, func() bool { return slices.Equal(fixed, []string{"1.44.1", "1.45.0"}) }
			},
		},
		{
			name: "an any slice",
			build: func() (any, func() bool) {
				fixed := []any{"1.44.1", "1.45.0"}
				return fixed, func() bool { return slices.Equal(fixed, []any{"1.44.1", "1.45.0"}) }
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixed, unchanged := tt.build()
			payload := map[string]any{
				"vulnerability": map[string]any{
					"package":  map[string]any{"ecosystem": "Go", "name": "github.com/aws/aws-sdk-go", "version": "1.44.0"},
					"advisory": map[string]any{"id": "GHSA-1", "fixed_versions": fixed},
				},
			}

			actions, err := eng.EvaluateAllMap(t.Context(), payload, "scan", EntrypointScanVulnerability.String())
			if err != nil {
				t.Fatalf("EvaluateAllMap: %v", err)
			}
			if len(actions) != 1 || actions[0].Type != ActionDeny {
				t.Errorf("rule on the canonical fixed version did not fire: actions=%v (fixed_versions %v)", actions, fixed)
			}
			if !unchanged() {
				t.Errorf("caller's fixed_versions slice was rewritten in place: %v", fixed)
			}
		})
	}
}

// TestPurlListsInTypedContainersAreCanonicalized pins the reference pass to the
// shape a caller actually hands it. "deputy scan --input" injects the SBOM's
// PURLs beside the packages it scanned as a []string ("sbom.purls", documented as
// normalized to canonical form), and the graph entrypoints name the direct
// dependencies the same way in "roots". The walk descended into map[string]any
// and []any only, so a typed string slice was skipped whole and a policy
// comparing a package against the list it belongs to read two spellings of one
// identity.
//
// The caller's slice is asserted unchanged: convertProtosInMap rebuilds a []any
// on the way in but passes a []string through by reference, so the list a caller
// still holds must not be rewritten under it.
func TestPurlListsInTypedContainersAreCanonicalized(t *testing.T) {
	const (
		raw       = "pkg:golang/example.com/mod@1.2.3"
		canonical = "pkg:golang/example.com/mod@v1.2.3"
	)
	identity := func() map[string]any {
		return map[string]any{"ecosystem": "Go", "name": "example.com/mod", "version": "1.2.3", "purl": raw}
	}

	tests := []struct {
		name    string
		body    string
		payload func(purls []string) map[string]any
	}{
		{
			name: "the scanned sbom's purl list",
			body: `pkg.purl in sbom.purls
  ? [{"action": "deny", "reason": "matched"}]
  : [{"action": "allow"}]`,
			payload: func(purls []string) map[string]any {
				return map[string]any{"pkg": identity(), "sbom": map[string]any{"purls": purls}}
			},
		},
		{
			name: "the graph's roots",
			body: `node.purl in roots
  ? [{"action": "deny", "reason": "matched"}]
  : [{"action": "allow"}]`,
			payload: func(purls []string) map[string]any {
				return map[string]any{"node": identity(), "roots": purls}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng, err := NewEngine([]Source{{Name: "purl-membership", Body: tt.body}})
			if err != nil {
				t.Fatalf("NewEngine() error: %v", err)
			}
			purls := []string{raw}
			actions, err := eng.EvaluateAllMap(t.Context(), tt.payload(purls), "scan", "")
			if err != nil {
				t.Fatalf("EvaluateAllMap: %v", err)
			}
			if len(actions) != 1 || actions[0].Type != ActionDeny {
				t.Errorf("membership rule did not fire: actions=%v (list %v, identity canonicalizes to %q)", actions, purls, canonical)
			}
			if !slices.Equal(purls, []string{raw}) {
				t.Errorf("caller's purl list was rewritten in place: %v", purls)
			}
		})
	}
}

// TestPackageReferencesLeaveEverythingElseAlone pins the blast radius of the
// reference pass, which is the half that widens the walk. It rewrites a string
// only when the string is a package URL of a type a registration claims, so
// caller data, prose, and package URLs of unknown types come back byte for byte
// even when they sit in a payload full of Go packages.
func TestPackageReferencesLeaveEverythingElseAlone(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
		want    map[string]any
	}{
		{
			name:    "a jwt claim holding a package url survives",
			payload: map[string]any{"jwt": map[string]any{"sub": "pkg:pypi/Flask_SQLAlchemy@3.1.1"}},
			want:    map[string]any{"jwt": map[string]any{"sub": "pkg:pypi/Flask_SQLAlchemy@3.1.1"}},
		},
		{
			name: "a free-form map holding a package url survives",
			payload: map[string]any{"node": map[string]any{
				"ecosystem":  "PyPI",
				"provenance": map[string]any{"origin": "pkg:pypi/zope.interface@6.4"},
			}},
			want: map[string]any{"node": map[string]any{
				"ecosystem":  "pypi",
				"provenance": map[string]any{"origin": "pkg:pypi/zope.interface@6.4"},
			}},
		},
		{
			name: "a package url of an unclaimed type survives",
			payload: map[string]any{"edge": map[string]any{
				"from": "pkg:github/Masterminds/semver@v3.2.1",
				"to":   "pkg:generic/Some_Thing@1.0",
			}},
			want: map[string]any{"edge": map[string]any{
				"from": "pkg:github/Masterminds/semver@v3.2.1",
				"to":   "pkg:generic/Some_Thing@1.0",
			}},
		},
		{
			name: "strings that are not package urls survive",
			payload: map[string]any{"edge": map[string]any{
				"from":       "example.com/Root",
				"to":         "https://example.com/pkg:pypi/Flask_SQLAlchemy",
				"constraint": ">=1.0.0",
			}},
			want: map[string]any{"edge": map[string]any{
				"from":       "example.com/Root",
				"to":         "https://example.com/pkg:pypi/Flask_SQLAlchemy",
				"constraint": ">=1.0.0",
			}},
		},
		{
			name: "target paths survive",
			payload: map[string]any{"target": map[string]any{
				"local_path": "/tmp/pkg:pypi",
				"origin_url": "https://github.com/temporalio/deputy",
			}},
			want: map[string]any{"target": map[string]any{
				"local_path": "/tmp/pkg:pypi",
				"origin_url": "https://github.com/temporalio/deputy",
			}},
		},
		{
			name: "a mismatched purl field still belongs to its own object",
			payload: map[string]any{"pkg": map[string]any{
				"ecosystem": "crates.io",
				"name":      "async-trait",
				"purl":      "pkg:pypi/Flask_SQLAlchemy@3.1.1",
			}},
			want: map[string]any{"pkg": map[string]any{
				"ecosystem": "cargo",
				"name":      "async-trait",
				"purl":      "pkg:pypi/Flask_SQLAlchemy@3.1.1",
			}},
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

// TestSiblingVersionSpellingsAgree pins the fields that repeat a version the
// payload already carries somewhere else. A Go fix verdict normalizes
// "resolved_fix.version" to "v1.2.0" while the advisory-claimed spelling in
// "resolved_fix.claimed" stayed "1.2.0", so a policy asking whether the
// verified version matched the claim compared two spellings of one version and
// took the wrong branch. The same shape holds for an SBOM package change and a
// freshness signal, both of which put two versions of one package side by side.
func TestSiblingVersionSpellingsAgree(t *testing.T) {
	tests := []struct {
		name    string
		object  map[string]any
		compare [2]string
		want    string
	}{
		{
			name: "unverified fix verdict",
			object: map[string]any{
				"ecosystem": "Go",
				"name":      "example.com/mod",
				"status":    "STATUS_UNVERIFIED",
				"version":   "1.2.0",
				"claimed":   "1.2.0",
			},
			compare: [2]string{"version", "claimed"},
			want:    "v1.2.0",
		},
		{
			name: "sbom package change",
			object: map[string]any{
				"ecosystem":        "Go",
				"name":             "example.com/mod",
				"previous_version": "1.2.0",
				"new_version":      "1.2.0",
			},
			compare: [2]string{"previous_version", "new_version"},
			want:    "v1.2.0",
		},
		{
			name: "freshness signal",
			object: map[string]any{
				"ecosystem":       "Go",
				"name":            "example.com/mod",
				"current_version": "1.2.0",
				"latest_version":  "1.2.0",
			},
			compare: [2]string{"current_version", "latest_version"},
			want:    "v1.2.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]any{"pkg": tt.object}
			canonicalizeEcosystemPayload(payload)
			left, right := tt.object[tt.compare[0]], tt.object[tt.compare[1]]
			if left != tt.want || right != tt.want {
				t.Errorf("%s = %v, %s = %v, want both %q", tt.compare[0], left, tt.compare[1], right, tt.want)
			}
		})
	}
}

// TestMigrationTargetModuleIsAPackageName pins the migration verdict's target
// against the module spelling a package fix uses, because a policy comparing
// resolved_fix.target_module with package_fixes[0].module is comparing one
// identity written two ways.
func TestMigrationTargetModuleIsAPackageName(t *testing.T) {
	payload := map[string]any{
		"pkg": map[string]any{
			"ecosystem": "PyPI",
			"name":      "Flask_SQLAlchemy",
			"resolved_fix": map[string]any{
				"status":        "STATUS_MIGRATION",
				"target_module": "Flask_SQLAlchemy2",
			},
			"package_fixes": []any{
				map[string]any{"module": "Flask_SQLAlchemy2"},
			},
		},
	}
	canonicalizeEcosystemPayload(payload)
	pkg := payload["pkg"].(map[string]any)
	verdict := pkg["resolved_fix"].(map[string]any)
	fix := pkg["package_fixes"].([]any)[0].(map[string]any)
	if got, want := verdict["target_module"], "flask-sqlalchemy2"; got != want {
		t.Errorf("resolved_fix.target_module = %v, want %q", got, want)
	}
	if verdict["target_module"] != fix["module"] {
		t.Errorf("resolved_fix.target_module = %v, package_fixes[0].module = %v, want them equal", verdict["target_module"], fix["module"])
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

// notPackageReference records, with a reason, the string fields whose own
// documentation mentions a package URL but which must not be canonicalized as a
// reference. Every one of them is a value a caller supplied and Deputy has to
// hand back or match byte for byte, or a field folded as a package name because
// it accepts a name just as readily as a PURL.
var notPackageReference = map[string]string{
	"path":          "a name the descriptors give a file path on every message a policy reads it from, so the walk cannot tell those from deputy.risk.v1.DependencyPath.path by the key alone",
	"query":         "an MCP result echoes the target purl exactly as the caller requested it",
	"package":       "a request input that accepts a name, name@version, or a PURL; folded as a package name",
	"dependency":    "a request input that accepts a name, name@version, or a PURL",
	"focus_package": "a request option that accepts a name or a PURL",
}

// TestReferenceKeysCoverSchema derives the reference vocabulary from the proto
// contract rather than trusting the list in [packageReferenceKeys] to be
// complete: every string field the protos themselves document as holding a
// package URL has to be classified, as an object's own identity
// ([packagePURLKeys]), as a reference to another package
// ([isPackageReferenceKey]), as a package name or version, or in
// [notPackageReference] with the reason it is none of those.
//
// The pass this guards decides what to rewrite from the field, not from the
// value, because a string that parses as a package URL is not necessarily one
// Deputy may rewrite: a sandbox request's argv can carry a package URL as an
// argument. That makes the list load-bearing in both directions, so an
// unclassified field is either a reference a policy reads in the wrong spelling
// or an argument authorization must see verbatim.
func TestReferenceKeysCoverSchema(t *testing.T) {
	versionKeys := append(slices.Clone(packageVersionKeys), packageVersionListKey)
	documented := make(map[string][]string)
	if err := descriptorset.RangeMessages(func(md protoreflect.MessageDescriptor) bool {
		fields := md.Fields()
		for i := range fields.Len() {
			f := fields.Get(i)
			if f.Kind() != protoreflect.StringKind || f.IsMap() {
				continue
			}
			comment := descriptorset.Comment(f.FullName())
			if !documentsPackageURL(comment) {
				continue
			}
			name := string(f.Name())
			switch {
			case isPackageReferenceKey(name),
				slices.Contains(packagePURLKeys, name),
				slices.Contains(packageNameKeys, name),
				slices.Contains(versionKeys, name):
				continue
			}
			if _, known := notPackageReference[name]; known {
				continue
			}
			documented[name] = append(documented[name], string(f.FullName()))
		}
		return true
	}); err != nil {
		t.Fatalf("RangeMessages: %v", err)
	}
	if len(documented) == 0 && len(packageReferenceKeys) == 0 {
		t.Fatal("no fields reached the reference coverage walk")
	}
	for _, name := range slices.Sorted(maps.Keys(documented)) {
		t.Errorf("%q is documented as holding a package URL (%v) but is not classified: add it to packageReferenceKeys if a policy should read it canonicalized, or to notPackageReference with the reason it must stay as it arrived",
			name, documented[name])
	}
}

// documentsPackageURL reports whether a proto field's own comment says the field
// holds a package URL, which is the only place that contract is written down.
func documentsPackageURL(comment string) bool {
	lower := strings.ToLower(comment)
	return strings.Contains(lower, "purl") || strings.Contains(lower, "package url")
}
