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
	source := `policies:
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
			yaml: `policies:
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
			name: "headers rejected",
			yaml: `policies:
  - name: noop
    rules:
      - action: deny
        when: true
`,
			wantErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "bundle.yaml")
			if err := os.WriteFile(path, []byte(test.yaml), 0o644); err != nil {
				t.Fatalf("write bundle: %v", err)
			}
			sources, err := LoadSources([]string{path})
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s", test.name)
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

// shippedPolicyPaths returns every policy bundle this repo ships, resolving the
// repo root from whichever directory the test binary runs in. Both the examples
// and the gates Deputy runs on its own PRs are included: policy/ci was outside
// the corpus when all three gates broke on a cel-go bump, so anything asserting
// a property of "our policies" has to cover it.
func shippedPolicyPaths(t *testing.T) []string {
	t.Helper()
	for _, prefix := range []string{"policy", "../policy", "../../policy"} {
		var paths []string
		for _, dir := range []string{"examples", "ci"} {
			matches, err := filepath.Glob(filepath.Join(prefix, dir, "*.yaml"))
			if err != nil {
				t.Fatalf("glob %s/%s: %v", prefix, dir, err)
			}
			paths = append(paths, matches...)
		}
		if len(paths) > 0 {
			return paths
		}
	}
	t.Fatal("no shipped policies found")
	return nil
}

func TestExampleBundlesCompile(t *testing.T) {
	t.Parallel()
	paths := shippedPolicyPaths(t)
	extraVars := []string{"licenses"}
	for _, path := range paths {
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

// receiverOf returns the receiver expression immediately preceding the
// ".orValue(" that ends at idx, by walking back over the identifier/selector
// chain. Stops at anything that cannot be part of a receiver path so that
// "a && b.orValue(x)" yields "b", not "a && b".
func receiverOf(expr string, idx int) string {
	start := idx
	depth := 0
	for start > 0 {
		c := expr[start-1]
		switch {
		case c == ')' || c == ']':
			depth++
		case c == '(' || c == '[':
			if depth == 0 {
				return expr[start:idx]
			}
			depth--
		case depth > 0:
			// inside a nested call or index; keep consuming
		case c == '.' || c == '?' || c == '_' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'):
			// part of the receiver path
		default:
			return expr[start:idx]
		}
		start--
	}
	return expr[start:idx]
}

// TestNoOrValueOnNonOptional pins the rule that .orValue() may only be applied
// to something that is actually optional, meaning the receiver chain contains
// a ?. select or a [?] index.
//
// Applying it to a plain variable is a silent no-op, not a default: through
// cel-go v0.26 the runtime handed the receiver back without ever evaluating
// the argument, and it does not rescue an unbound variable either, because
// attribute resolution fails before the call. cel-go v0.28 turned the same
// expression into "no such overload", which broke all three CI gates at once.
//
// Neither a compile check nor an eval check catches this on the pinned
// version, since the bad form both compiles and evaluates there. A static
// check is the only thing that holds across cel-go versions.
func TestNoOrValueOnNonOptional(t *testing.T) {
	t.Parallel()
	for _, path := range shippedPolicyPaths(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			for i, line := range strings.Split(string(body), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue // comment, not an expression
				}
				for _, m := range orValueSites(line) {
					if !strings.Contains(m, "?") {
						t.Errorf("%s:%d: .orValue() applied to non-optional receiver %q; "+
							"guard the hop that can actually be absent (x.?y.orValue(z)) or drop the call",
							filepath.Base(path), i+1, m)
					}
				}
			}
		})
	}
}

// orValueSites returns the receiver of every ".orValue(" occurrence in line.
func orValueSites(line string) []string {
	const marker = ".orValue("
	var out []string
	for off := 0; ; {
		j := strings.Index(line[off:], marker)
		if j < 0 {
			return out
		}
		at := off + j
		out = append(out, receiverOf(line, at))
		off = at + len(marker)
	}
}
