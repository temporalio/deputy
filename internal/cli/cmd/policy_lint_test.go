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
			name: "unrelated defects are all reported in one run",
			bundle: `policies:
  - name: two-defects
    mode: enfroce
    rules:
      - when: "true"
        action: dney
        reason: "x"
`,
			wantFail: true,
			wantText: []string{
				`policy "two-defects": invalid mode "enfroce"`,
				`policy "two-defects" rule[0]: invalid action "dney"`,
				"2 policy problem(s) found",
			},
		},
		{
			name: "a mistyped field still yields located errors",
			bundle: `policies:
  - name: typed-error
    mode: enfroce
    rules:
      - when: "true"
        action: dney
        reason: "x"
        status: "four-oh-three"
`,
			wantFail: true,
			wantText: []string{
				`policy "typed-error": invalid mode "enfroce"`,
				`policy "typed-error" rule[0]: invalid action "dney"`,
				"line 8: cannot unmarshal",
			},
		},
		{
			name: "a missing when does not hide a bad action",
			bundle: `policies:
  - name: both-defects
    rules:
      - action: dney
        reason: "no when and a bad action"
`,
			wantFail: true,
			wantText: []string{
				"rule missing 'when' expression",
				`invalid action "dney"`,
				"2 policy problem(s) found",
			},
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
			// The per-issue lines go to stdout and the summary comes back as the
			// command error, so both are what the user sees.
			reported := out
			if err != nil {
				reported += err.Error()
			}
			for _, want := range tc.wantText {
				if !strings.Contains(reported, want) {
					t.Fatalf("output missing %q:\n%s", want, reported)
				}
			}
		})
	}
}

// TestPolicyAnchorsRejectedByBothCommands pins that lint and bundle refuse the
// same YAML constructs with the same message. Anchors are deliberately not part
// of the bundle format, and the two commands must not disagree about that: a
// bundle that compiles but does not lint, or the reverse, is the divergence this
// restriction exists to prevent.
func TestPolicyAnchorsRejectedByBothCommands(t *testing.T) {
	cases := []struct {
		name     string
		bundle   string
		wantText string
	}{
		{
			name: "aliased policy",
			bundle: `base: &base
  name: aliased
  rules:
    - when: "true"
      action: deny
      reason: "r"

policies:
  - *base
`,
			wantText: "do not support YAML anchors and aliases",
		},
		{
			name: "merge key",
			bundle: `defaults: &defaults
  rules:
    - when: "true"
      action: deny
      reason: "r"

policies:
  - <<: *defaults
    name: inherits
`,
			wantText: "do not support YAML merge keys",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "policy.yaml")
			if err := os.WriteFile(path, []byte(tc.bundle), 0o600); err != nil {
				t.Fatalf("write policy: %v", err)
			}

			lintOut, lintErr := runPolicyLint(t, tc.bundle)
			if lintErr == nil {
				t.Fatalf("expected lint to fail, output:\n%s", lintOut)
			}
			if !strings.Contains(lintOut, tc.wantText) {
				t.Fatalf("lint output missing %q:\n%s", tc.wantText, lintOut)
			}
			if !strings.Contains(lintOut, "--policy file") || !strings.Contains(lintOut, "vars:") {
				t.Fatalf("lint output should point at the alternatives:\n%s", lintOut)
			}

			bundleRoot := &cobra.Command{Use: "deputy"}
			bundleRoot.AddCommand(newPolicyBundleCommand())
			var bundleOut bytes.Buffer
			bundleRoot.SetOut(&bundleOut)
			bundleRoot.SetErr(&bundleOut)
			bundleRoot.SetArgs([]string{"bundle", "--output", filepath.Join(dir, "out.json"), path})
			err := bundleRoot.Execute()
			if err == nil {
				t.Fatalf("expected bundle to fail, output:\n%s", bundleOut.String())
			}
			// Lint lists every construct it finds while the loader stops at the
			// first, so the loader's message has to be one lint also printed.
			_, message, found := strings.Cut(err.Error(), "policy bundles do not support YAML")
			if !found {
				t.Fatalf("bundle error %q should refuse the construct by name", err)
			}
			if !strings.Contains(lintOut, "policy bundles do not support YAML"+message) {
				t.Fatalf("bundle error %q is not among the messages lint printed:\n%s", err, lintOut)
			}
		})
	}
}

// TestPolicyLintAcceptsCompiledBundle pins the round trip documented in the
// policy framework reference: what `deputy policy bundle` writes must lint
// clean. A compiled bundle is JSON, and JSON is valid YAML with a "policies"
// array, so the structured probe has to tell the two shapes apart.
func TestPolicyLintAcceptsCompiledBundle(t *testing.T) {
	dir := t.TempDir()
	authored := filepath.Join(dir, "authored.yaml")
	if err := os.WriteFile(authored, []byte(`policies:
  - name: block-left-pad
    entrypoints: ["scan_vulnerability"]
    vars:
      blocked: '["left-pad"]'
    rules:
      - when: "pkg.name in blocked"
        action: deny
        reason: "blocked package"
`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	compiled := filepath.Join(dir, "compiled.json")

	bundleRoot := &cobra.Command{Use: "deputy"}
	bundleRoot.AddCommand(newPolicyBundleCommand())
	var bundleOut bytes.Buffer
	bundleRoot.SetOut(&bundleOut)
	bundleRoot.SetErr(&bundleOut)
	bundleRoot.SetArgs([]string{"bundle", "--output", compiled, authored})
	if err := bundleRoot.Execute(); err != nil {
		t.Fatalf("policy bundle: %v\n%s", err, bundleOut.String())
	}

	lintRoot := &cobra.Command{Use: "deputy"}
	lintRoot.AddCommand(newPolicyLintCommand())
	var lintOut bytes.Buffer
	lintRoot.SetOut(&lintOut)
	lintRoot.SetErr(&lintOut)
	lintRoot.SetArgs([]string{"lint", compiled})
	if err := lintRoot.Execute(); err != nil {
		t.Fatalf("lint of compiled bundle failed: %v\n%s", err, lintOut.String())
	}
	if !strings.Contains(lintOut.String(), "OK") {
		t.Fatalf("expected compiled bundle to lint OK, got:\n%s", lintOut.String())
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

// TestPolicyLintReportsYAMLSyntaxErrors pins that a bundle whose YAML does not
// parse is reported as the syntax error it is, naming the offending line, rather
// than dismissed as an unrecognized format. The editor validates the same
// document directly and has always named the line, so anything else leaves the
// CLI and the editor disagreeing about a file the author plainly wrote as a
// policy.
func TestPolicyLintReportsYAMLSyntaxErrors(t *testing.T) {
	cases := []struct {
		name     string
		bundle   string
		wantText []string
	}{
		{
			name:     "an unterminated rules list",
			bundle:   "policies:\n  - name: broken\n    rules: [\n",
			wantText: []string{"line 3"},
		},
		{
			name:     "an unterminated policies list",
			bundle:   "policies: [\n  - name: broken\n",
			wantText: []string{"line 1"},
		},
		{
			name:     "a value the parser cannot read",
			bundle:   "policies:\n  - name: broken\n     rules: []\n",
			wantText: []string{"line 3"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runPolicyLint(t, tc.bundle)
			if err == nil {
				t.Fatalf("expected lint to fail, got:\n%s", out)
			}
			combined := out + err.Error()
			if strings.Contains(combined, "unrecognized policy format") {
				t.Fatalf("expected a YAML syntax error, got the unknown-format fallback:\n%s", combined)
			}
			for _, want := range tc.wantText {
				if !strings.Contains(combined, want) {
					t.Fatalf("expected %q in output, got:\n%s", want, combined)
				}
			}
		})
	}
}
