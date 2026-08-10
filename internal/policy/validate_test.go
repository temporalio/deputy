package policy

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// TestValidateBundle pins the vocabulary and structure checks that both the
// linter and the editor rely on, including the ones a CEL-only check misses.
func TestValidateBundle(t *testing.T) {
	cases := []struct {
		name         string
		bundle       string
		wantCodes    []string
		unwantedCode string
		wantText     []string
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
			name: "a missing when does not hide a missing action",
			bundle: `
policies:
  - name: empty-rule
    rules:
      - reason: "nothing here"
`,
			wantCodes: []string{"missing-when", "missing-action"},
		},
		{
			name: "a missing when does not hide a bad action",
			bundle: `
policies:
  - name: both-defects
    rules:
      - action: dney
        reason: "no when and a bad action"
`,
			wantCodes: []string{"missing-when", "invalid-action"},
			wantText:  []string{"rule missing 'when' expression", `invalid action "dney"`},
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
			name: "invalid mode",
			bundle: `
policies:
  - name: bad-mode
    mode: enfroce
    rules:
      - when: "true"
        action: deny
        reason: "x"
`,
			wantCodes: []string{"invalid-mode"},
			wantText:  []string{`4:11: error: policy "bad-mode": invalid mode "enfroce" (expected advisory|enforce)`},
		},
		{
			name: "two unrelated defects are reported in one pass",
			bundle: `
policies:
  - name: two-defects
    mode: enfroce
    rules:
      - when: "true"
        action: dney
        reason: "x"
`,
			wantCodes: []string{"invalid-mode", "invalid-action"},
			wantText:  []string{`invalid mode "enfroce"`, `invalid action "dney"`},
		},
		{
			name: "a typed field error does not hide located defects",
			bundle: `
policies:
  - name: typed-error
    mode: enfroce
    rules:
      - when: "true"
        action: dney
        reason: "x"
        status: "four-oh-three"
`,
			wantCodes: []string{"invalid-mode", "invalid-action", "bundle-error"},
			wantText:  []string{`invalid mode "enfroce"`, `invalid action "dney"`, "cannot unmarshal"},
		},
		{
			name: "duplicate var names",
			bundle: `
policies:
  - name: dup-vars
    vars:
      blocked: '["a"]'
      blocked: '["b"]'
    rules:
      - when: "true"
        action: deny
        reason: "x"
`,
			wantCodes: []string{"duplicate-var"},
			wantText:  []string{`duplicate var name "blocked"`},
		},
		{
			name: "empty rules list",
			bundle: `
policies:
  - name: no-rules
    rules: []
`,
			wantCodes: []string{"empty-rules"},
			wantText:  []string{"policy must contain at least one rule"},
		},
		{
			name: "loader backstop covers shapes the walk does not model",
			bundle: `
policies:
  - name: bad-status
    rules:
      - when: "true"
        action: deny
        reason: "x"
        status: "four-oh-three"
`,
			wantCodes: []string{"bundle-error"},
		},
		{
			name:      "missing policies list",
			bundle:    "rules: []\n",
			wantCodes: []string{"missing-policies"},
		},
		{
			name: "a policy written as an alias is rejected",
			bundle: `
base: &base
  name: aliased
  entrypoints: ["scan_vulnerability"]
  rules:
    - when: "true"
      action: deny
      reason: "aliased policy"

policies:
  - *base
`,
			wantCodes: []string{"yaml-anchor"},
			wantText:  []string{"do not support YAML anchors and aliases", "--policy file", "vars:"},
		},
		{
			name: "a merge key is rejected",
			bundle: `
defaults: &defaults
  entrypoints: ["scan_vulnerability"]
  rules:
    - when: "true"
      action: deny
      reason: "inherited rule"

policies:
  - <<: *defaults
    name: inherits-rules
`,
			wantCodes: []string{"yaml-anchor", "yaml-merge-key"},
			wantText:  []string{"do not support YAML merge keys"},
		},
		{
			name: "an unused anchor definition is rejected",
			bundle: `
unused: &unused
  name: never-referenced

policies:
  - name: plain
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
			wantCodes: []string{"yaml-anchor"},
		},
		{
			name:      "an anchored policies list is rejected",
			bundle:    "policies: &loop\n  - *loop\n",
			wantCodes: []string{"yaml-anchor"},
		},
		{
			name: "an anchor does not hide an unrelated defect",
			bundle: `
unused: &unused
  reason: "shared"

policies:
  - name: plain
    mode: adivsory
    rules:
      - when: "true"
        action: dney
        reason: "r"
`,
			wantCodes: []string{"yaml-anchor", "invalid-action", "invalid-mode"},
		},
		{
			name: "an aliased policy is reported only as an alias",
			bundle: `
base: &base
  name: aliased
  rules:
    - when: "true"
      action: dney
      reason: "r"

policies:
  - *base
`,
			wantCodes:    []string{"yaml-anchor"},
			unwantedCode: "policy-not-mapping",
		},
		{
			name:      "a policies mapping is reported by shape",
			bundle:    "policies: {}\n",
			wantCodes: []string{"policies-not-list"},
			wantText:  []string{"'policies' must be a list"},
		},
		{
			name:      "a policies scalar is reported by shape",
			bundle:    "policies: none\n",
			wantCodes: []string{"policies-not-list"},
		},
		{
			name:      "an empty policies list is reported",
			bundle:    "policies: []\n",
			wantCodes: []string{"empty-policies"},
			wantText:  []string{"at least one policy"},
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
			if tc.unwantedCode != "" && slices.Contains(codes, tc.unwantedCode) {
				t.Fatalf("issue code %q should not be reported, got %v:\n%s", tc.unwantedCode, codes, rendered.String())
			}
			for _, want := range tc.wantText {
				if !strings.Contains(rendered.String(), want) {
					t.Fatalf("expected output to mention %q, got:\n%s", want, rendered.String())
				}
			}
		})
	}
}

// TestAnchorsRejectedAtEveryPosition pins that an anchor is refused wherever it
// can appear, by both readers, with the same message. An alias is a node kind,
// so it can stand in for a policy, a rule, a list item, a var value, or any
// scalar, and a reader that resolves it at one position and rejects it at
// another is the divergence this restriction removes: before the format refused
// them, `rules: [*rule]` loaded fine and linted as "rule must be a mapping".
func TestAnchorsRejectedAtEveryPosition(t *testing.T) {
	cases := []struct {
		name     string
		bundle   string
		wantCode string
	}{
		{
			name: "a policy item",
			bundle: `
base: &base
  name: aliased
  rules:
    - when: "true"
      action: deny
      reason: "r"

policies:
  - *base
`,
			wantCode: "yaml-anchor",
		},
		{
			name: "an individual rule item",
			bundle: `
sharedRule: &rule
  when: "true"
  action: deny
  reason: "r"

policies:
  - name: alias-rule-item
    rules: [*rule]
`,
			wantCode: "yaml-anchor",
		},
		{
			name: "the rules list itself",
			bundle: `
sharedRules: &rules
  - when: "true"
    action: deny
    reason: "r"

policies:
  - name: alias-rules-list
    rules: *rules
`,
			wantCode: "yaml-anchor",
		},
		{
			name: "a vars value",
			bundle: `
blockedList: &blocked '["left-pad"]'

policies:
  - name: alias-var-value
    vars:
      blocked: *blocked
    rules:
      - when: "pkg.name in blocked"
        action: deny
        reason: "r"
`,
			wantCode: "yaml-anchor",
		},
		{
			name: "the vars mapping itself",
			bundle: `
sharedVars: &vars
  blocked: '["left-pad"]'

policies:
  - name: alias-vars-mapping
    vars: *vars
    rules:
      - when: "pkg.name in blocked"
        action: deny
        reason: "r"
`,
			wantCode: "yaml-anchor",
		},
		{
			name: "a nested sequence item",
			bundle: `
eco: &eco "npm"

policies:
  - name: alias-nested-seq
    ecosystems: [*eco]
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
			wantCode: "yaml-anchor",
		},
		{
			name: "a scalar field",
			bundle: `
policyName: &name "aliased-name"

policies:
  - name: *name
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
			wantCode: "yaml-anchor",
		},
		{
			name:     "the policies list itself",
			bundle:   "policies: &loop\n  - *loop\n",
			wantCode: "yaml-anchor",
		},
		{
			name: "an anchor that is never referenced",
			bundle: `
unused: &unused
  name: never-referenced

policies:
  - name: plain
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
			wantCode: "yaml-anchor",
		},
		{
			name: "a merge key on a policy",
			bundle: `
defaults: &defaults
  rules:
    - when: "true"
      action: deny
      reason: "r"

policies:
  - <<: *defaults
    name: merged-policy
`,
			wantCode: "yaml-merge-key",
		},
		{
			name: "a merge key inside a rule",
			bundle: `
ruleDefaults: &ruleDefaults
  action: deny
  reason: "r"

policies:
  - name: merged-rule
    rules:
      - <<: *ruleDefaults
        when: "true"
`,
			wantCode: "yaml-merge-key",
		},
		{
			name: "the policies key itself supplied by a root merge key",
			bundle: `
defaults: &defaults
  policies:
    - name: inherited
      rules:
        - when: "true"
          action: deny
          reason: "r"

<<: *defaults
`,
			wantCode: "yaml-merge-key",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, err := ValidateBundle(tc.bundle, ValidateOptions{Source: "bundle.yaml"})
			if err != nil {
				t.Fatalf("ValidateBundle: %v", err)
			}
			var codes []string
			for _, issue := range issues {
				codes = append(codes, issue.Code)
			}
			if !slices.Contains(codes, tc.wantCode) {
				t.Fatalf("expected issue code %q, got %v: %v", tc.wantCode, codes, issues)
			}
			for _, issue := range issues {
				if issue.Line <= 0 {
					t.Fatalf("issue %v should name the line the construct is on", issue)
				}
			}

			// The loader has to refuse the same document, or a bundle that lints
			// as broken would still compile.
			_, loadErr := ParseStructuredSources([]byte(tc.bundle), "bundle.yaml")
			if loadErr == nil {
				t.Fatal("expected the loader to reject the bundle too")
			}
			if !strings.Contains(loadErr.Error(), "policy bundles do not support YAML") {
				t.Fatalf("loader error %q should refuse the construct by name", loadErr)
			}
			for _, want := range []string{"--policy file", "vars:"} {
				if !strings.Contains(loadErr.Error(), want) {
					t.Fatalf("loader error %q should point at %q", loadErr, want)
				}
				if !strings.Contains(issues[0].Message, want) {
					t.Fatalf("issue message %q should point at %q", issues[0].Message, want)
				}
			}
		})
	}
}

// TestValidateBundleAgreesWithLoader pins the equivalence the two paths must
// keep: a bundle the loader compiles has to validate clean, and one the loader
// rejects has to be reported. Validation walks YAML nodes while the loader
// decodes into Go types, and the decoder resolves anchors for free, so the
// constructs the format refuses have to be refused by both. This test is what
// makes that refusal safe to rely on.
func TestValidateBundleAgreesWithLoader(t *testing.T) {
	cases := []struct {
		name   string
		bundle string
	}{
		{
			name: "plain policy",
			bundle: `
policies:
  - name: plain
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
		},
		{
			name: "policy written as an alias",
			bundle: `
base: &base
  name: aliased
  rules:
    - when: "true"
      action: deny
      reason: "r"

policies:
  - *base
`,
		},
		{
			name: "fields inherited through a merge key",
			bundle: `
defaults: &defaults
  rules:
    - when: "true"
      action: deny
      reason: "r"

policies:
  - <<: *defaults
    name: inherits
`,
		},
		{
			name: "rules supplied by an alias",
			bundle: `
sharedRules: &sharedRules
  - when: "true"
    action: warn
    reason: "r"

policies:
  - name: alias-rules
    rules: *sharedRules
`,
		},
		{
			name: "unknown action inside an anchor",
			bundle: `
base: &base
  name: aliased
  rules:
    - when: "true"
      action: dney
      reason: "r"

policies:
  - *base
`,
		},
		{
			name:   "an anchored policies list",
			bundle: "policies: &loop\n  - *loop\n",
		},
		{
			name: "an unused anchor definition",
			bundle: `
unused: &unused
  name: never-referenced

policies:
  - name: plain
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
		},
		{
			name: "a plain policy alongside an unknown action",
			bundle: `
policies:
  - name: typo
    rules:
      - when: "true"
        action: dney
        reason: "r"
`,
		},
		{
			name: "policy names that differ only by surrounding whitespace",
			bundle: `
policies:
  - name: same
    rules:
      - when: "true"
        action: deny
        reason: "r"
  - name: "  same  "
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
		},
		{
			name: "a policies list supplied by a root merge key",
			bundle: `
defaults: &defaults
  policies:
    - name: inherited
      rules:
        - when: "true"
          action: deny
          reason: "r"

<<: *defaults
`,
		},
		{
			name:   "a policies key written as a mapping",
			bundle: "policies: {}\n",
		},
		{
			name:   "an empty policies list",
			bundle: "policies: []\n",
		},
		{
			name: "optional fields written as an explicit null",
			bundle: `
policies:
  - name: explicit-nulls
    mode: null
    entrypoints: null
    commands: null
    vars: null
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
		},
		{
			name: "optional fields written as a tilde",
			bundle: `
policies:
  - name: tilde-nulls
    mode: ~
    entrypoints: ~
    commands: ~
    vars: ~
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
		},
		{
			name: "optional fields written with no value at all",
			bundle: `
policies:
  - name: bare-keys
    mode:
    entrypoints:
    commands:
    vars:
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
		},
		{
			name: "two policies whose names are an explicit null",
			bundle: `
policies:
  - name: null
    rules:
      - when: "true"
        action: deny
        reason: "r"
  - name: null
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
		},
		{
			name: "two policies whose names are a tilde",
			bundle: `
policies:
  - name: ~
    rules:
      - when: "true"
        action: deny
        reason: "r"
  - name: ~
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
		},
		{
			name: "a rule whose condition is an explicit null",
			bundle: `
policies:
  - name: null-when
    rules:
      - when: null
        action: deny
        reason: "r"
`,
		},
		{
			name: "a rule whose action is an explicit null",
			bundle: `
policies:
  - name: null-action
    rules:
      - when: "true"
        action: null
        reason: "r"
`,
		},
		{
			name: "a rules list written as an explicit null",
			bundle: `
policies:
  - name: null-rules
    rules: null
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, loadErr := ParseStructuredSources([]byte(tc.bundle), "bundle.yaml")
			issues, err := ValidateBundle(tc.bundle, ValidateOptions{Source: "bundle.yaml"})
			if err != nil {
				t.Fatalf("ValidateBundle: %v", err)
			}
			reported := slices.ContainsFunc(issues, func(i Issue) bool { return i.Severity != IssueHint })
			if reported != (loadErr != nil) {
				t.Fatalf("validation reported=%v but loader error=%v; issues=%v", reported, loadErr, issues)
			}
		})
	}
}

// TestValidateBundleAgreesWithCompilation pins the promise lint makes to an
// author: a bundle that lints clean is a bundle `deputy policy bundle` can
// compile. Rule conditions are checked one at a time, but a policy's vars wrap
// every condition in a CEL comprehension, so a var whose value or name is not
// valid CEL breaks only the body the policy expands into and is invisible to the
// per-rule check.
func TestValidateBundleAgreesWithCompilation(t *testing.T) {
	cases := []struct {
		name   string
		bundle string
	}{
		{
			name: "a policy with usable vars",
			bundle: `
policies:
  - name: usable-vars
    vars:
      blocked: '["left-pad"]'
    rules:
      - when: "pkg.name in blocked"
        action: deny
        reason: "r"
`,
		},
		{
			name: "a var holding invalid CEL",
			bundle: `
policies:
  - name: broken-var
    vars:
      threshold: '1 +'
    rules:
      - when: "true"
        action: warn
        reason: "r"
`,
		},
		{
			name: "a var name CEL cannot bind",
			bundle: `
policies:
  - name: broken-var-name
    vars:
      not-an-identifier: '1'
    rules:
      - when: "true"
        action: warn
        reason: "r"
`,
		},
		{
			name: "a plain policy with no vars",
			bundle: `
policies:
  - name: plain
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, err := ValidateBundle(tc.bundle, ValidateOptions{Source: "bundle.yaml"})
			if err != nil {
				t.Fatalf("ValidateBundle: %v", err)
			}
			reported := slices.ContainsFunc(issues, func(i Issue) bool { return i.Severity != IssueHint })
			compiles := true
			sources, loadErr := ParseStructuredSources([]byte(tc.bundle), "bundle.yaml")
			if loadErr != nil {
				compiles = false
			}
			for _, src := range sources {
				if Compile(src.Body, nil) != nil {
					compiles = false
				}
			}
			if reported == compiles {
				t.Fatalf("validation reported=%v but the bundle compiles=%v; issues=%v", reported, compiles, issues)
			}
		})
	}
}

// TestLooksLikeStructuredBundle pins the shape probe callers use to decide
// whether a file is an authored policy. It must say yes for a policy that does
// not decode, so validation still runs and reports the offending field, and no
// for a compiled bundle, whose JSON also carries a "policies" array.
func TestLooksLikeStructuredBundle(t *testing.T) {
	cases := []struct {
		name string
		data string
		want bool
	}{
		{
			name: "authored bundle",
			data: "policies:\n  - name: p\n    rules:\n      - when: \"true\"\n        action: deny\n        reason: r\n",
			want: true,
		},
		{
			name: "authored bundle with a mistyped field",
			data: "policies:\n  - name: p\n    rules:\n      - when: \"true\"\n        action: deny\n        reason: r\n        status: \"four-oh-three\"\n",
			want: true,
		},
		{
			name: "authored bundle with a malformed vars block",
			data: "policies:\n  - name: p\n    vars: [1, 2]\n    rules:\n      - when: \"true\"\n        action: deny\n        reason: r\n",
			want: true,
		},
		{
			name: "compiled bundle",
			data: `{"schemaVersion":"policy.deputy.sh/v1alpha1","policies":[{"name":"c","source":"[]"}]}`,
		},
		{
			name: "raw CEL",
			data: `pkg.name == "left-pad" ? [{"action": "deny"}] : []`,
		},
		{
			name: "empty policies list",
			data: "policies: []\n",
			want: true,
		},
		{
			name: "policies written as a mapping",
			data: "policies: {}\n",
			want: true,
		},
		{
			name: "policies written as a scalar",
			data: "policies: none\n",
			want: true,
		},
		{
			name: "a bundle whose YAML does not parse",
			data: "policies: [\n  - name: broken\n",
			want: true,
		},
		{
			name: "a bundle whose YAML does not parse below the policies key",
			data: "policies:\n  - name: broken\n    rules: [\n",
			want: true,
		},
		{
			name: "a bundle whose double-quoted policies key precedes a syntax error",
			data: "\"policies\":\n  - name: broken\n    rules: [\n",
			want: true,
		},
		{
			name: "a bundle whose single-quoted policies key precedes a syntax error",
			data: "'policies':\n  - name: broken\n    rules: [\n",
			want: true,
		},
		{
			name: "a document whose unparsed key only starts with the bundle key",
			data: "policiesx:\n  - name: broken\n    rules: [\n",
		},
		{
			name: "a document that quotes a key the bundle does not have",
			data: "\"rules\":\n  - when: [\n",
		},
		{
			name: "raw CEL that does not parse as YAML",
			data: "// policy: legacy\npkg.name == \"left-pad\"\n  ? [{\"action\": \"deny\"}]\n  : []\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := LooksLikeStructuredBundle([]byte(tc.data)); got != tc.want {
				t.Fatalf("LooksLikeStructuredBundle = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestValidateBundleReportsEachDefectOnce pins that the loader backstop does not
// restate a defect the node walk already located, so a single mistake produces a
// single issue.
func TestValidateBundleReportsEachDefectOnce(t *testing.T) {
	cases := []struct {
		name   string
		bundle string
	}{
		{
			name: "unknown action",
			bundle: `
policies:
  - name: once
    rules:
      - when: "true"
        action: dney
        reason: "x"
`,
		},
		{
			name: "unknown entrypoint",
			bundle: `
policies:
  - name: once
    entrypoints: ["scan_vulnerabilities"]
    rules:
      - when: "true"
        action: deny
        reason: "x"
`,
		},
		{
			name: "invalid mode",
			bundle: `
policies:
  - name: once
    mode: enfroce
    rules:
      - when: "true"
        action: deny
        reason: "x"
`,
		},
		{
			name: "empty rules",
			bundle: `
policies:
  - name: once
    rules: []
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, err := ValidateBundle(tc.bundle, ValidateOptions{})
			if err != nil {
				t.Fatalf("ValidateBundle: %v", err)
			}
			if len(issues) != 1 {
				t.Fatalf("expected exactly one issue, got %d: %v", len(issues), issues)
			}
			if issues[0].Code == "bundle-error" {
				t.Fatalf("expected a located issue, got the loader backstop: %v", issues[0])
			}
		})
	}
}

// TestValidateBundleRejectsCompiledBundle pins that a bundle compiled by
// `deputy policy bundle` is not mistaken for an authored one. Its JSON parses as
// YAML and has a "policies" array, so without the check every entry would be
// reported as a policy missing its rules.
func TestValidateBundleRejectsCompiledBundle(t *testing.T) {
	compiled := `{
  "schemaVersion": "policy.deputy.sh/v1alpha1",
  "generated": "2026-01-01T00:00:00Z",
  "policies": [
    {"name": "compiled", "source": "[] + ((true) ? [{\"action\":\"deny\"}] : [])"}
  ]
}`
	issues, err := ValidateBundle(compiled, ValidateOptions{})
	if err == nil {
		t.Fatalf("expected compiled bundle to be rejected, got issues %v", issues)
	}
	if !strings.Contains(err.Error(), "compiled policy bundle") {
		t.Fatalf("error %q should name the compiled bundle shape", err)
	}
	if _, parsed, _ := TryParseStructuredBundleBytes([]byte(compiled)); parsed {
		t.Fatal("compiled bundle must not be reported as a structured bundle")
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

// TestValidateBundleChecksEveryHealthyPolicy pins that one broken policy does
// not hide a defect in another. Expansion failures are suppressed for the policy
// the node walk already reported, because restating that failure in expanded CEL
// the author never wrote obscures the real defect, but every other policy in the
// bundle is still expanded and compiled. Without that the author fixes one
// policy, reruns lint, and is handed the next one.
//
// The suppression is per policy whatever the defect: a field the decoder refuses
// and an anchor the format refuses are both reported alongside the rest of the
// bundle, not instead of it. Reading the whole bundle to expand it is what made
// those two swallow every later diagnostic, since the loader stops at its first
// failure.
func TestValidateBundleChecksEveryHealthyPolicy(t *testing.T) {
	cases := []struct {
		name         string
		bundle       string
		wantPolicies []string
		wantCodes    []string
	}{
		{
			name: "a bad var behind a policy with a bad condition",
			bundle: `
policies:
  - name: bad-condition
    rules:
      - when: "this is not cel"
        action: deny
        reason: "r"
  - name: bad-var
    vars:
      threshold: '1 +'
    rules:
      - when: "true"
        action: warn
        reason: "r"
`,
			wantPolicies: []string{"bad-condition", "bad-var"},
		},
		{
			name: "a bad var ahead of a policy with a bad condition",
			bundle: `
policies:
  - name: bad-var-name
    vars:
      not-an-identifier: '1'
    rules:
      - when: "true"
        action: warn
        reason: "r"
  - name: bad-condition
    rules:
      - when: "this is not cel"
        action: deny
        reason: "r"
`,
			wantPolicies: []string{"bad-var-name", "bad-condition"},
		},
		{
			name: "two policies whose vars hold invalid CEL",
			bundle: `
policies:
  - name: first-bad-var
    vars:
      threshold: '1 +'
    rules:
      - when: "true"
        action: warn
        reason: "r"
  - name: second-bad-var
    vars:
      ceiling: '* 2'
    rules:
      - when: "true"
        action: warn
        reason: "r"
`,
			wantPolicies: []string{"first-bad-var", "second-bad-var"},
		},
		{
			name: "a bad var behind a policy whose field the decoder refuses",
			bundle: `
policies:
  - name: bad-status
    rules:
      - when: "true"
        action: deny
        reason: "r"
        status: "four-oh-three"
  - name: bad-var
    vars:
      threshold: '1 +'
    rules:
      - when: "true"
        action: warn
        reason: "r"
`,
			wantPolicies: []string{"bad-var"},
			wantCodes:    []string{"bundle-error", "cel-error"},
		},
		{
			name: "a bad var alongside a refused anchor",
			bundle: `
unused: &unused
  name: never-referenced

policies:
  - name: bad-var
    vars:
      threshold: '1 +'
    rules:
      - when: "true"
        action: warn
        reason: "r"
`,
			wantPolicies: []string{"bad-var"},
			wantCodes:    []string{"yaml-anchor", "cel-error"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, err := ValidateBundle(tc.bundle, ValidateOptions{Source: "bundle.yaml"})
			if err != nil {
				t.Fatalf("ValidateBundle: %v", err)
			}
			for _, want := range tc.wantPolicies {
				found := slices.ContainsFunc(issues, func(i Issue) bool {
					return i.Policy == want && i.Severity == IssueError
				})
				if !found {
					t.Fatalf("expected an error on policy %q, got %v", want, issues)
				}
			}
			for _, want := range tc.wantCodes {
				if !slices.ContainsFunc(issues, func(i Issue) bool { return i.Code == want }) {
					t.Fatalf("expected an issue with code %q, got %v", want, issues)
				}
			}
		})
	}
}

// TestBundleKeyMatchesStructTag pins the shape probe's key to the field the
// decoder actually reads. The probe recognizes an authored bundle by that key,
// including in the raw text of a document YAML cannot parse, so a rename of the
// struct tag alone would leave every bundle unrecognized.
func TestBundleKeyMatchesStructTag(t *testing.T) {
	field, ok := reflect.TypeFor[structuredBundle]().FieldByName("Policies")
	if !ok {
		t.Fatal("structuredBundle has no Policies field")
	}
	tag, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
	if tag != bundlePoliciesKey {
		t.Fatalf("bundlePoliciesKey = %q but the yaml tag is %q", bundlePoliciesKey, tag)
	}
}
