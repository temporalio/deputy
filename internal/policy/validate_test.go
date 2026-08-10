package policy

import (
	"slices"
	"strings"
	"testing"
)

// TestValidateBundle pins the vocabulary and structure checks that both the
// linter and the editor rely on, including the ones a CEL-only check misses.
func TestValidateBundle(t *testing.T) {
	cases := []struct {
		name      string
		bundle    string
		wantCodes []string
		wantText  []string
	}{
		{
			name: "valid policy has no issues",
			bundle: `
policies:
  - name: ok
    entrypoints: ["scan_vulnerability"]
    rules:
      - when: 'vulnerability.advisory.id == "CVE-2024-1"'
        action: deny
        reason: "known bad"
`,
		},
		{
			name: "unknown action",
			bundle: `
policies:
  - name: typo-action
    rules:
      - when: "true"
        action: dney
        reason: "should deny"
`,
			wantCodes: []string{"invalid-action"},
			wantText:  []string{`invalid action "dney"`, "allow|deny|warn", `policy "typo-action" rule[0]`},
		},
		{
			name: "unknown entrypoint",
			bundle: `
policies:
  - name: typo-entrypoint
    entrypoints: ["scan_vulnerabilities"]
    rules:
      - when: "true"
        action: deny
        reason: "x"
`,
			wantCodes: []string{"invalid-entrypoint"},
			wantText:  []string{`invalid entrypoint "scan_vulnerabilities"`},
		},
		{
			name: "unknown command",
			bundle: `
policies:
  - name: typo-command
    commands: ["scna"]
    rules:
      - when: "true"
        action: deny
        reason: "x"
`,
			wantCodes: []string{"invalid-command"},
			wantText:  []string{`invalid command "scna"`},
		},
		{
			name: "duplicate policy names",
			bundle: `
policies:
  - name: same
    rules:
      - when: "true"
        action: deny
        reason: "x"
  - name: same
    rules:
      - when: "true"
        action: deny
        reason: "y"
`,
			wantCodes: []string{"duplicate-policy"},
			wantText:  []string{`duplicate policy name "same"`},
		},
		{
			name: "unbound variable in condition",
			bundle: `
policies:
  - name: unbound
    rules:
      - when: "vulnerabilty.advisory.id != ''"
        action: deny
        reason: "x"
`,
			wantCodes: []string{"cel-error"},
			wantText:  []string{"undeclared reference", `policy "unbound" rule[0]`},
		},
		{
			name: "missing when and action",
			bundle: `
policies:
  - name: empty-rule
    rules:
      - reason: "nothing here"
`,
			wantCodes: []string{"missing-when"},
		},
		{
			name: "missing action",
			bundle: `
policies:
  - name: no-action
    rules:
      - when: "true"
        reason: "x"
`,
			wantCodes: []string{"missing-action"},
		},
		{
			name: "deny without reason is a hint",
			bundle: `
policies:
  - name: no-reason
    rules:
      - when: "true"
        action: deny
`,
			wantCodes: []string{"missing-reason"},
		},
		{
			name: "invalid mode is reported by the loader",
			bundle: `
policies:
  - name: bad-mode
    mode: enfroce
    rules:
      - when: "true"
        action: deny
        reason: "x"
`,
			wantCodes: []string{"bundle-error"},
			wantText:  []string{`invalid mode "enfroce"`},
		},
		{
			name:      "missing policies list",
			bundle:    "rules: []\n",
			wantCodes: []string{"missing-policies"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, err := ValidateBundle(tc.bundle, ValidateOptions{})
			if err != nil {
				t.Fatalf("ValidateBundle: %v", err)
			}
			codes := make([]string, 0, len(issues))
			var rendered strings.Builder
			for _, issue := range issues {
				codes = append(codes, issue.Code)
				rendered.WriteString(issue.String())
				rendered.WriteString("\n")
			}
			if len(tc.wantCodes) == 0 && len(issues) != 0 {
				t.Fatalf("expected no issues, got:\n%s", rendered.String())
			}
			for _, want := range tc.wantCodes {
				if !slices.Contains(codes, want) {
					t.Fatalf("expected issue code %q, got %v:\n%s", want, codes, rendered.String())
				}
			}
			for _, want := range tc.wantText {
				if !strings.Contains(rendered.String(), want) {
					t.Fatalf("expected output to mention %q, got:\n%s", want, rendered.String())
				}
			}
		})
	}
}

// TestValidateBundleRejectsNonYAML pins that unparseable input is an error rather
// than a silently clean bundle.
func TestValidateBundleRejectsNonYAML(t *testing.T) {
	if _, err := ValidateBundle("policies: [\n  - name: broken\n", ValidateOptions{}); err == nil {
		t.Fatal("expected error for malformed YAML")
	}
}

// TestValidateBundleDeclaresPolicyVars pins that vars declared by the policy are
// in scope for its conditions, so lint does not report them as unbound.
func TestValidateBundleDeclaresPolicyVars(t *testing.T) {
	bundle := `
policies:
  - name: with-vars
    vars:
      blocked: '["left-pad"]'
    rules:
      - when: "pkg.name in blocked"
        action: deny
        reason: "blocked package"
`
	issues, err := ValidateBundle(bundle, ValidateOptions{})
	if err != nil {
		t.Fatalf("ValidateBundle: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("expected no issues, got %v", issues)
	}
}

// TestValidateBundleExtraVars pins that caller-declared names (lint --var) are in
// scope too.
func TestValidateBundleExtraVars(t *testing.T) {
	bundle := `
policies:
  - name: extra-vars
    rules:
      - when: "custom_input == 1"
        action: warn
        reason: "custom"
`
	issues, err := ValidateBundle(bundle, ValidateOptions{ExtraVars: []string{"custom_input"}})
	if err != nil {
		t.Fatalf("ValidateBundle: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("expected no issues with extra var declared, got %v", issues)
	}
}
