package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractPolicyName(t *testing.T) {
	src := `//! policy.name = "foo-policy"
true`
	if got := extractPolicyName(src); got != "foo-policy" {
		t.Fatalf("extractPolicyName() = %q, want foo-policy", got)
	}
}

func TestBuildBundle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	source := `apiVersion: policy.deputy.sh/v1alpha2
kind: PolicyBundle
policies:
  - name: bundle-policy
    rules:
      - action: allow
        when: true
`
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	bundle, err := BuildBundle([]string{path})
	if err != nil {
		t.Fatalf("BuildBundle() error = %v", err)
	}
	if bundle.SchemaVersion == "" {
		t.Fatalf("expected schema version, got empty")
	}
	if len(bundle.Policies) != 1 {
		t.Fatalf("expected 1 policy in bundle, got %d", len(bundle.Policies))
	}
	if bundle.Policies[0].Name != "bundle-policy" {
		t.Fatalf("unexpected policy name %q", bundle.Policies[0].Name)
	}
	if bundle.Policies[0].Source == "" {
		t.Fatalf("expected policy source to be stored")
	}
}

func TestLoadStructuredBundle(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{
			name: "valid",
			yaml: `apiVersion: policy.deputy.sh/v1alpha2
kind: PolicyBundle
policies:
  - name: block-log4shell
    description: Block vulnerable log4j packages
    ecosystems: [npm]
    vars:
      badAliases: '["CVE-2021-44228"]'
    rules:
      - action: deny
        when: vulnerabilities.exists(v, v.Aliases.exists(a, a in badAliases))
        reason: log4shell vulnerability
        status: 451
        headers:
          X-Deputy-Policy: log4shell
`,
		},
		{
			name: "bad schema",
			yaml: `apiVersion: policy.deputy.sh/v1beta1
kind: PolicyBundle
policies:
  - name: noop
    rules:
      - action: deny
        when: true
`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "bundle.yaml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0o644); err != nil {
				t.Fatalf("write bundle: %v", err)
			}
			sources, err := LoadSources([]string{path})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s", tt.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadSources() error = %v", err)
			}
			if len(sources) != 1 {
				t.Fatalf("expected 1 source, got %d", len(sources))
			}
			body := sources[0].Body
			if !strings.Contains(body, "policy.name") {
				t.Fatalf("metadata missing from body: %s", body)
			}
			if err := Compile(body, nil); err != nil {
				t.Fatalf("compiled structured policy invalid: %v", err)
			}
		})
	}
}

func TestExampleBundlesCompile(t *testing.T) {
	t.Parallel()
	patterns := []string{
		"policy/examples/*.yaml",
		"../policy/examples/*.yaml",
		"../../policy/examples/*.yaml",
	}
	var paths []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		if len(matches) > 0 {
			paths = matches
			break
		}
	}
	if len(paths) == 0 {
		t.Fatalf("no example policies found")
	}
	extraVars := []string{"licenses"}
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			sources, err := LoadSources([]string{path})
			if err != nil {
				t.Fatalf("LoadSources(%s): %v", path, err)
			}
			if len(sources) == 0 {
				t.Fatalf("no sources returned for %s", path)
			}
			for _, src := range sources {
				if err := Compile(src.Body, extraVars); err != nil {
					t.Fatalf("compile %s: %v", src.Name, err)
				}
			}
		})
	}
}
