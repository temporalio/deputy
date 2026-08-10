package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runPolicyLint writes a bundle to a temp file, lints it, and returns the
// command output plus whether the run failed.
func runPolicyLint(t *testing.T, bundle string, args ...string) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	root := &cobra.Command{Use: "deputy"}
	root.AddCommand(newPolicyLintCommand())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{"lint", path}, args...))
	err := root.Execute()
	return strings.ReplaceAll(out.String(), path, "POLICY"), err
}

// TestPolicyLintValidatesBeyondCEL pins that lint fails on the vocabulary and
// structure mistakes a CEL-only check waves through, and that its output names
// the file, the policy, and the rule.
func TestPolicyLintValidatesBeyondCEL(t *testing.T) {
	cases := []struct {
		name     string
		bundle   string
		wantFail bool
		wantText []string
	}{
		{
			name: "valid policy reports OK",
			bundle: `policies:
  - name: ok
    entrypoints: ["scan_vulnerability"]
    rules:
      - when: "true"
        action: deny
        reason: "always"
`,
			wantText: []string{"POLICY OK"},
		},
		{
			name: "unknown action fails",
			bundle: `policies:
  - name: typo-action
    rules:
      - when: "true"
        action: dney
        reason: "should deny"
`,
			wantFail: true,
			wantText: []string{"POLICY:5:17", `policy "typo-action" rule[0]`, `invalid action "dney"`, "allow|deny|warn"},
		},
		{
			name: "unknown entrypoint fails",
			bundle: `policies:
  - name: typo-entrypoint
    entrypoints: ["scan_vulnerabilities"]
    rules:
      - when: "true"
        action: deny
        reason: "x"
`,
			wantFail: true,
			wantText: []string{`policy "typo-entrypoint"`, `invalid entrypoint "scan_vulnerabilities"`},
		},
		{
			name: "unbound variable fails",
			bundle: `policies:
  - name: unbound
    rules:
      - when: "vulnerabilty.advisory.id != ''"
        action: deny
        reason: "x"
`,
			wantFail: true,
			wantText: []string{`policy "unbound" rule[0]`, "undeclared reference"},
		},
		{
			name: "duplicate policy names fail",
			bundle: `policies:
  - name: same
    rules:
      - when: "true"
        action: deny
        reason: "x"
  - name: same
    rules:
      - when: "true"
        action: warn
        reason: "y"
`,
			wantFail: true,
			wantText: []string{`duplicate policy name "same"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runPolicyLint(t, tc.bundle)
			if tc.wantFail && err == nil {
				t.Fatalf("expected lint to fail, output:\n%s", out)
			}
			if !tc.wantFail && err != nil {
				t.Fatalf("lint failed unexpectedly: %v\n%s", err, out)
			}
			for _, want := range tc.wantText {
				if !strings.Contains(out, want) {
					t.Fatalf("output missing %q:\n%s", want, out)
				}
			}
		})
	}
}

// TestPolicyLintAcceptsDeclaredVars pins that --var keeps caller-declared names
// from being reported as unbound.
func TestPolicyLintAcceptsDeclaredVars(t *testing.T) {
	bundle := `policies:
  - name: extra
    rules:
      - when: "custom_input == 1"
        action: warn
        reason: "custom"
`
	out, err := runPolicyLint(t, bundle, "--var", "custom_input")
	if err != nil {
		t.Fatalf("lint failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "POLICY OK") {
		t.Fatalf("expected OK, got:\n%s", out)
	}
}
