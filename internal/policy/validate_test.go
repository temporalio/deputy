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
			name: "a details value that cannot be represented",
			bundle: `
policies:
  - name: nan-details
    rules:
      - when: "true"
        action: deny
        reason: "x"
        details:
          score: .nan
`,
			wantCodes: []string{"details-not-representable"},
			wantText:  []string{"9:11: error: policy \"nan-details\" rule[0]: 'details' holds a value that cannot be represented"},
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

// TestMergeKeysRefusedByTagNotByText pins that a merge key is recognized by the
// tag YAML resolves for it and not by the text it is spelled with. A quoted "<<"
// is an ordinary string key: yaml.v3 tags it !!str and the decoder keeps it as a
// key rather than merging anything, so a bundle whose free-form metadata or rule
// details carry that name says nothing about a merge and has to lint and load.
// Refusing it on the text alone named a construct the author did not write, and
// withheld every other diagnostic for the policy carrying it, since the checks
// that read a document's values step over the nodes a merge key makes unreadable.
//
// Every spelling the decoder does merge is still refused, whatever value it
// merges from and however the tag is written, which is what keeps the tag a safe
// signal to gate on. The two directions are pinned together so the check cannot
// pass by accepting both. TestAnchorsRejectedAtEveryPosition covers the positions
// a merge key can take; this covers the spellings.
func TestMergeKeysRefusedByTagNotByText(t *testing.T) {
	const plainPolicy = `
policies:
  - name: plain
    rules:
      - when: "true"
        action: deny
        reason: "r"
`
	cases := []struct {
		name    string
		bundle  string
		refused bool
	}{
		{
			name:   "a double-quoted key named << in bundle metadata",
			bundle: "metadata:\n  \"<<\": literal\n" + plainPolicy,
		},
		{
			name:   "a single-quoted key named << in bundle metadata",
			bundle: "metadata:\n  '<<': literal\n" + plainPolicy,
		},
		{
			name: "a quoted key named << in a rule's details",
			bundle: `
policies:
  - name: quoted-detail
    rules:
      - when: "true"
        action: deny
        reason: "r"
        details:
          "<<": literal
`,
		},
		{
			name:    "a merge key with a mapping value",
			bundle:  "metadata:\n  <<: {inherited: 1}\n" + plainPolicy,
			refused: true,
		},
		{
			name: "a merge key with an alias value",
			bundle: `
base: &base
  inherited: 1

metadata:
  <<: *base
` + plainPolicy,
			refused: true,
		},
		{
			name: "a merge key with a sequence of aliases",
			bundle: `
base: &base
  inherited: 1

metadata:
  <<: [*base]
` + plainPolicy,
			refused: true,
		},
		{
			name:    "a merge key tagged explicitly on a quoted key",
			bundle:  "metadata:\n  !!merge \"<<\": {inherited: 1}\n" + plainPolicy,
			refused: true,
		},
		{
			name:    "a merge key tagged with the verbatim tag URI",
			bundle:  "metadata:\n  !<tag:yaml.org,2002:merge> \"<<\": {inherited: 1}\n" + plainPolicy,
			refused: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, err := ValidateBundle(tc.bundle, ValidateOptions{Source: "bundle.yaml"})
			if err != nil {
				t.Fatalf("ValidateBundle: %v", err)
			}
			sources, loadErr := ParseStructuredSources([]byte(tc.bundle), "bundle.yaml")
			if !tc.refused {
				if len(issues) != 0 {
					t.Fatalf("a key named << is not a merge key: %v", issues)
				}
				if loadErr != nil {
					t.Fatalf("the loader refused a key named <<: %v", loadErr)
				}
				if len(sources) != 1 {
					t.Fatalf("expected one compiled source, got %d", len(sources))
				}
				return
			}
			if !slices.ContainsFunc(issues, func(i Issue) bool { return i.Code == "yaml-merge-key" }) {
				t.Fatalf("expected the merge key to be reported, got %v", issues)
			}
			// The loader has to refuse the same document, or a merge would expand
			// into policy content nobody reviewed. It names the first refused
			// construct, which is the anchor the merge inherits from when the
			// document defines one, so the wording is pinned to the family and the
			// merge key itself to the located diagnostic above.
			if loadErr == nil {
				t.Fatalf("expected the loader to refuse the merge key, got %d sources", len(sources))
			}
			if !strings.Contains(loadErr.Error(), "policy bundles do not support YAML") {
				t.Fatalf("loader error %q should refuse the construct by name", loadErr)
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
			name: "var names that differ only by surrounding whitespace",
			bundle: `
policies:
  - name: padded-var-names
    vars:
      blocked: '["left-pad"]'
      " blocked ": '["right-pad"]'
    rules:
      - when: "pkg.name in blocked"
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
			name: "a var name padded with whitespace",
			bundle: `
policies:
  - name: padded-var-name
    vars:
      " blocked ": '["left-pad"]'
    rules:
      - when: "pkg.name in blocked"
        action: deny
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
			name: "an indented bundle key preceding a syntax error",
			data: "  policies:\n    - name: broken\n      rules: [\n",
			want: true,
		},
		{
			name: "an indented bundle key below a comment, preceding a syntax error",
			data: "# a bundle\n  policies:\n    - name: broken\n      rules: [\n",
			want: true,
		},
		{
			name: "an indented bundle key in a document that parses",
			data: "  policies:\n    - name: p\n      rules:\n        - when: \"true\"\n          action: deny\n          reason: r\n",
			want: true,
		},
		{
			name: "a policies list inherited through a merge key",
			data: "defaults: &d\n  policies:\n    - name: p\n      rules:\n        - when: \"true\"\n          action: deny\n          reason: r\n\n<<: *d\n",
			want: true,
		},
		{
			name: "an empty policies list inherited through a merge key",
			data: "defaults: &d\n  policies: []\n\n<<: *d\n",
			want: true,
		},
		{
			name: "a malformed policies value inherited through a merge key",
			data: "defaults: &d\n  policies: {}\n\n<<: *d\n",
			want: true,
		},
		{
			name: "a document whose unparsed key only starts with the bundle key",
			data: "policiesx:\n  - name: broken\n    rules: [\n",
		},
		{
			name: "a nested policies key in a document that does not parse",
			data: "wrapper:\n  policies:\n    - name: broken\n      rules: [\n",
		},
		{
			name: "raw CEL whose map literal keys the bundle key",
			data: "// policy: legacy\npkg.name in {\"policies\": [\"left-pad\"]}.policies\n  ? [{\"action\": \"deny\"}]\n  : []\n",
		},
		{
			name: "raw CEL whose map literal keys the bundle key on its own line",
			data: "// policy: legacy\nsize(request.x) > 0 && {\n  \"policies\": [\"left-pad\"]\n}.policies.size() > 0\n  ? [{\"action\": \"deny\"}]\n  : []\n",
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
		{
			name: "missing rules",
			bundle: `
policies:
  - name: once
`,
		},
		{
			name: "rules written as a mapping",
			bundle: `
policies:
  - name: once
    rules: {}
`,
		},
		{
			name: "rules written as a block mapping",
			bundle: `
policies:
  - name: once
    rules:
      when: "true"
`,
		},
		{
			name: "rules written as a scalar",
			bundle: `
policies:
  - name: once
    rules: "when true deny"
`,
		},
		{
			name:   "policies written as a mapping",
			bundle: "\npolicies: {}\n",
		},
		{
			name:   "policies written as a scalar",
			bundle: "\npolicies: none\n",
		},
		{
			name:   "an empty policies list",
			bundle: "\npolicies: []\n",
		},
		{
			name:   "a policies entry that is not a policy",
			bundle: "\npolicies:\n  - not-a-policy\n",
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

// TestValidateBundleFoldsOnlyTheRestatedDefect pins that folding a loader
// restatement drops that restatement alone. The decoder reports every field it
// refuses in one error, so a defect the node walk already located travels
// alongside defects only the decoder finds, and dropping the whole error would
// hide them until the located one is fixed and lint rerun.
func TestValidateBundleFoldsOnlyTheRestatedDefect(t *testing.T) {
	cases := []struct {
		name       string
		bundle     string
		wantIssues int
		wantCodes  []string
		wantText   []string
		denyText   []string
	}{
		{
			name: "bundle metadata of the wrong type beside a non-list rules value",
			bundle: `
metadata: []

policies:
  - name: once
    rules: {}
`,
			wantIssues: 2,
			wantCodes:  []string{"rules-not-list", "bundle-error"},
			wantText:   []string{"line 2: cannot unmarshal"},
			denyText:   []string{"structuredRule"},
		},
		{
			name: "bundle metadata of the wrong type beside a non-list policies value",
			bundle: `
metadata: []
policies: {}
`,
			wantIssues: 2,
			wantCodes:  []string{"policies-not-list", "bundle-error"},
			wantText:   []string{"line 2: cannot unmarshal"},
			denyText:   []string{"structuredPolicy"},
		},
		{
			name: "bundle metadata of the wrong type beside an empty policies list",
			bundle: `
metadata: []
policies: []
`,
			wantIssues: 2,
			wantCodes:  []string{"empty-policies", "bundle-error"},
			wantText:   []string{"line 2: cannot unmarshal"},
		},
		{
			name: "bundle metadata of the wrong type beside a missing policies list",
			bundle: `
metadata: []
`,
			wantIssues: 2,
			wantCodes:  []string{"missing-policies", "bundle-error"},
			wantText:   []string{"line 2: cannot unmarshal"},
		},
		{
			name: "two policies whose fields the decoder refuses",
			bundle: `
policies:
  - name: first
    rules:
      - when: "true"
        action: deny
        reason: "r"
        status: nope
  - name: second
    rules:
      - when: "true"
        action: deny
        reason: "r"
        status: nah
`,
			wantIssues: 2,
			wantCodes:  []string{"bundle-error"},
			wantText:   []string{"nope", "nah"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, err := ValidateBundle(tc.bundle, ValidateOptions{})
			if err != nil {
				t.Fatalf("ValidateBundle: %v", err)
			}
			if len(issues) != tc.wantIssues {
				t.Fatalf("expected %d issues, got %d: %v", tc.wantIssues, len(issues), issues)
			}
			for _, want := range tc.wantCodes {
				if !slices.ContainsFunc(issues, func(i Issue) bool { return i.Code == want }) {
					t.Fatalf("expected an issue with code %q, got %v", want, issues)
				}
			}
			var reported strings.Builder
			for _, issue := range issues {
				reported.WriteString(issue.Message)
				reported.WriteString("\n")
			}
			for _, want := range tc.wantText {
				if !strings.Contains(reported.String(), want) {
					t.Fatalf("expected the report to mention %q, got %v", want, issues)
				}
			}
			for _, deny := range tc.denyText {
				if strings.Contains(reported.String(), deny) {
					t.Fatalf("the report restates %q the walk already located: %v", deny, issues)
				}
			}
		})
	}
}

// TestValidateBundleKeepsComplaintsSharingALocatedLine pins that folding a
// loader restatement is keyed on the value the located issue describes and not on
// the line it sits on. A line carries more than one field whenever the author
// writes a policy in flow style, and the line a missing rules list is reported on
// is the policy's first field whatever that field is, so a fold keyed on the line
// alone drops a defect only the decoder finds and hands it back one lint run
// later. Each case pairs a shape the walk locates with a mistyped field the walk
// does not model, and the last case is the same mistyped field on its own, so the
// pairing is what the assertion turns on.
func TestValidateBundleKeepsComplaintsSharingALocatedLine(t *testing.T) {
	cases := []struct {
		name      string
		bundle    string
		wantCodes []string
		denyText  []string
	}{
		{
			name:      "a mistyped field beside a rules value that is not a list",
			bundle:    "\npolicies:\n  - {name: once, description: [1], rules: 5}\n",
			wantCodes: []string{"rules-not-list", "bundle-error"},
			denyText:  []string{"structuredRule"},
		},
		{
			name:      "a mistyped field on the line a missing rules list is reported",
			bundle:    "\npolicies:\n  - description: [1]\n    name: once\n",
			wantCodes: []string{"missing-rules", "bundle-error"},
		},
		{
			name:      "a mistyped field beside an empty rules list",
			bundle:    "\npolicies:\n  - {name: once, description: [1], rules: []}\n",
			wantCodes: []string{"empty-rules", "bundle-error"},
		},
		{
			name:      "a mistyped field beside a policies entry that is not a policy",
			bundle:    "\npolicies: [1, {name: once, description: [1], rules: 5}]\n",
			wantCodes: []string{"policy-not-mapping", "rules-not-list", "bundle-error"},
			denyText:  []string{"structuredPolicy"},
		},
		{
			name:      "the mistyped field on its own",
			bundle:    "\npolicies:\n  - name: once\n    description: [1]\n    rules:\n      - when: \"true\"\n        action: deny\n        reason: r\n",
			wantCodes: []string{"bundle-error"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, err := ValidateBundle(tc.bundle, ValidateOptions{})
			if err != nil {
				t.Fatalf("ValidateBundle: %v", err)
			}
			if len(issues) != len(tc.wantCodes) {
				t.Fatalf("expected %d issues, got %d: %v", len(tc.wantCodes), len(issues), issues)
			}
			for _, want := range tc.wantCodes {
				if !slices.ContainsFunc(issues, func(i Issue) bool { return i.Code == want }) {
					t.Fatalf("expected an issue with code %q, got %v", want, issues)
				}
			}
			var reported strings.Builder
			for _, issue := range issues {
				reported.WriteString(issue.Message)
				reported.WriteString("\n")
			}
			if !strings.Contains(reported.String(), "cannot unmarshal !!seq into string") {
				t.Fatalf("expected the report to name the mistyped field, got %v", issues)
			}
			for _, deny := range tc.denyText {
				if strings.Contains(reported.String(), deny) {
					t.Fatalf("the report restates %q the walk already located: %v", deny, issues)
				}
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

// TestValidateBundleReportsIndependentDefects pins that one defect does not
// withhold the diagnostics for an unrelated one anywhere in a document. Anchors,
// aliases, and merge keys are refused wherever they appear, but refusing them is
// a diagnostic like any other: it must not cost the author a lint run per defect
// on parts of the document that are written plainly and read the same either
// way. A policy's vars are independent of its rules for the same reason, since
// they are wrong or right on their own.
// TestValidateBundleAsksEveryVarItsOwnQuestion pins that each var of a policy is
// reported on its own terms: the name it binds, and separately the expression it
// holds. A name the policy cannot bind does not withhold the expression beside it,
// and the expression is compiled in the scope it would have been evaluated in,
// which is the vars declared above it. Compiling it anywhere else would invent a
// diagnostic: a name the file declares below cannot be read from above, and a
// repeated name is read from the declaration already in scope.
func TestValidateBundleAsksEveryVarItsOwnQuestion(t *testing.T) {
	cases := []struct {
		name      string
		vars      string
		wantCodes []string
		denyCodes []string
		wantText  []string
	}{
		{
			name:      "an unnamed var holding an uncompilable expression",
			vars:      "      \"\": 'no_such_function()'\n      good: '1'\n",
			wantCodes: []string{"empty-var-name", "cel-error"},
			wantText:  []string{"no_such_function"},
		},
		{
			name:      "an unnamed var holding an expression that compiles",
			vars:      "      \"\": '1'\n      good: '1'\n",
			wantCodes: []string{"empty-var-name"},
			denyCodes: []string{"cel-error"},
		},
		{
			name:      "an unnamed var reading a name declared below it",
			vars:      "      \"\": 'good'\n      good: '1'\n",
			wantCodes: []string{"empty-var-name", "cel-error"},
			wantText:  []string{"undeclared reference to 'good'"},
		},
		{
			name:      "a repeated name whose expression reads the declaration above it",
			vars:      "      dup: '1'\n      dup: 'dup + 1'\n",
			wantCodes: []string{"duplicate-var"},
			denyCodes: []string{"cel-error"},
		},
		{
			name:      "a repeated name holding an uncompilable expression",
			vars:      "      dup: '1'\n      dup: 'no_such_function()'\n",
			wantCodes: []string{"duplicate-var", "cel-error"},
			wantText:  []string{"no_such_function"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bundle := "policies:\n  - name: vars\n    vars:\n" + tc.vars +
				"    rules:\n      - when: \"true\"\n        action: deny\n        reason: r\n"
			issues, err := ValidateBundle(bundle, ValidateOptions{Source: "bundle.yaml"})
			if err != nil {
				t.Fatalf("ValidateBundle: %v", err)
			}
			var reported strings.Builder
			for _, issue := range issues {
				reported.WriteString(issue.Message)
				reported.WriteString("\n")
			}
			for _, want := range tc.wantCodes {
				if !slices.ContainsFunc(issues, func(i Issue) bool { return i.Code == want }) {
					t.Fatalf("expected an issue with code %q, got %v", want, issues)
				}
			}
			for _, deny := range tc.denyCodes {
				if slices.ContainsFunc(issues, func(i Issue) bool { return i.Code == deny }) {
					t.Fatalf("did not expect an issue with code %q, got %v", deny, issues)
				}
			}
			for _, want := range tc.wantText {
				if !strings.Contains(reported.String(), want) {
					t.Fatalf("expected the report to mention %q, got %v", want, issues)
				}
			}
			// A var the policy cannot bind is never a var the policy may run.
			if _, loadErr := ParseStructuredSources([]byte(bundle), "bundle.yaml"); loadErr == nil {
				t.Fatal("expected the loader to refuse the bundle")
			}
		})
	}
}

func TestValidateBundleReportsIndependentDefects(t *testing.T) {
	cases := []struct {
		name      string
		bundle    string
		wantCodes []string
	}{
		{
			name: "a var holding invalid CEL beside a bad action",
			bundle: `
policies:
  - name: bad-var-and-action
    vars:
      threshold: '1 +'
    rules:
      - when: "true"
        action: dney
        reason: "r"
`,
			wantCodes: []string{"invalid-action", "cel-error"},
		},
		{
			name: "a var name CEL cannot bind beside a missing rules list",
			bundle: `
policies:
  - name: bad-var-name-and-no-rules
    vars:
      not-an-identifier: '1'
`,
			wantCodes: []string{"missing-rules", "cel-error"},
		},
		{
			name: "a var holding invalid CEL beside a field the decoder refuses",
			bundle: `
policies:
  - name: bad-var-and-status
    vars:
      threshold: '1 +'
    rules:
      - when: "true"
        action: deny
        reason: "r"
        status: nope
`,
			wantCodes: []string{"bundle-error", "cel-error"},
		},
		{
			name: "a var holding invalid CEL beside an unknown entrypoint",
			bundle: `
policies:
  - name: bad-var-and-entrypoint
    entrypoints: ["scan_vulnerabilities"]
    vars:
      threshold: '1 +'
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
			wantCodes: []string{"invalid-entrypoint", "cel-error"},
		},
		{
			name: "an anchored field beside a bad action in the same policy",
			bundle: `
policies:
  - name: anchored-description
    description: &text foo
    rules:
      - when: "true"
        action: dney
        reason: "r"
`,
			wantCodes: []string{"yaml-anchor", "invalid-action"},
		},
		{
			name: "an anchored field beside a bad mode and an uncompilable condition",
			bundle: `
policies:
  - name: anchored-scalar
    mode: &m enfroce
    rules:
      - when: "this is not cel"
        action: deny
        reason: "r"
`,
			wantCodes: []string{"yaml-anchor", "invalid-mode", "cel-error"},
		},
		{
			name: "an anchored policy beside a policy written as an alias",
			bundle: `
policies:
  - &base
    name: anchored-policy
    rules:
      - when: "true"
        action: dney
        reason: "r"
  - *base
`,
			wantCodes: []string{"yaml-anchor", "invalid-action"},
		},
		{
			name: "an unused anchor beside a policies mapping",
			bundle: `
unused: &u 1

policies: {}
`,
			wantCodes: []string{"yaml-anchor", "policies-not-list"},
		},
		{
			name: "an unused anchor beside a policies scalar",
			bundle: `
unused: &u 1

policies: none
`,
			wantCodes: []string{"yaml-anchor", "policies-not-list"},
		},
		{
			name: "an unused anchor beside bundle metadata of the wrong type",
			bundle: `
unused: &u 1

metadata: []

policies:
  - name: plain
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
			wantCodes: []string{"yaml-anchor", "bundle-error"},
		},
		{
			name: "an unused anchor in a document with no policies key",
			bundle: `
unused: &u
  name: never-referenced
`,
			wantCodes: []string{"yaml-anchor", "missing-policies"},
		},
		{
			// The decoder reads a null key as the empty name every reader of a
			// bundle refuses, so the walk has to read it the same way and locate
			// it, rather than leaving it to a backstop an unrelated defect stops.
			name: "an explicitly null var name beside a bad action",
			bundle: `
policies:
  - name: null-var-name-and-action
    vars:
      null: pkg.name
    rules:
      - when: "true"
        action: dney
        reason: "r"
`,
			wantCodes: []string{"empty-var-name", "invalid-action"},
		},
		{
			name: "a var name written as a tilde beside a bad action",
			bundle: `
policies:
  - name: tilde-var-name-and-action
    vars:
      ~: pkg.name
    rules:
      - when: "true"
        action: dney
        reason: "r"
`,
			wantCodes: []string{"empty-var-name", "invalid-action"},
		},
		{
			// The details of a rule are marshaled into the action the policy
			// generates, so a value JSON has no spelling for stops the whole
			// expansion. It is a defect of that field alone, and the expansion
			// refuses the action above it first, so the walk has to locate it or
			// the author fixes the action to be told about the details.
			name: "a details value that cannot be represented beside a bad action",
			bundle: `
policies:
  - name: nan-details-and-action
    rules:
      - when: "true"
        action: dney
        reason: "r"
        details:
          score: .nan
`,
			wantCodes: []string{"invalid-action", "details-not-representable"},
		},
		{
			// A name the policy cannot bind is a defect of that one var, so the
			// vars under it are still compiled: reporting them a lint run later
			// makes the author fix a file one name at a time.
			name: "a var with no name beside a var that does not compile",
			bundle: `
policies:
  - name: unnamed-var-and-bad-var
    vars:
      "": '1'
      threshold: '1 +'
    rules:
      - when: "threshold > 0"
        action: deny
        reason: "r"
`,
			wantCodes: []string{"empty-var-name", "cel-error"},
		},
		{
			name: "a duplicate var name beside a var that does not compile",
			bundle: `
policies:
  - name: duplicate-var-and-bad-var
    vars:
      blocked: '["a"]'
      blocked: '["b"]'
      threshold: '1 +'
    rules:
      - when: "threshold > 0"
        action: deny
        reason: "r"
`,
			wantCodes: []string{"duplicate-var", "cel-error"},
		},
		{
			name: "two var names the policy cannot bind beside a var that does not compile",
			bundle: `
policies:
  - name: two-bad-names-and-bad-var
    vars:
      "": '1'
      blocked: '["a"]'
      blocked: '["b"]'
      threshold: '1 +'
    rules:
      - when: "threshold > 0"
        action: deny
        reason: "r"
`,
			wantCodes: []string{"empty-var-name", "duplicate-var", "cel-error"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, err := ValidateBundle(tc.bundle, ValidateOptions{Source: "bundle.yaml"})
			if err != nil {
				t.Fatalf("ValidateBundle: %v", err)
			}
			for _, want := range tc.wantCodes {
				if !slices.ContainsFunc(issues, func(i Issue) bool { return i.Code == want }) {
					t.Fatalf("expected an issue with code %q, got %v", want, issues)
				}
			}
			for _, issue := range issues {
				if issue.Line <= 0 {
					t.Fatalf("issue %v should name the line it is on", issue)
				}
			}
		})
	}
}

// TestValidateBundleChecksBundleShapesBesideAReference pins that a reference the
// format refuses does not withhold the bundle-level shapes only decoding finds. An
// alias or a merge key is a refusal like any other: the author has to remove it,
// and being told nothing else about the file until they do costs a lint run per
// defect. The decoder resolves what no reader of a bundle may, but an anchor is
// defined in the same document, so every line it names is a line the author wrote.
//
// The last case is the same bundle without the reference, so what the reference was
// withholding is what the assertion turns on.
func TestValidateBundleChecksBundleShapesBesideAReference(t *testing.T) {
	cases := []struct {
		name      string
		bundle    string
		wantCodes []string
		wantText  []string
	}{
		{
			name: "an alias elsewhere in the document",
			bundle: `
unused: &u 1
also: *u

metadata: []

policies:
  - name: plain
    rules:
      - when: "true"
        action: deny
        reason: r
`,
			wantCodes: []string{"yaml-anchor", "bundle-error"},
			wantText:  []string{"line 5: cannot unmarshal"},
		},
		{
			name: "a merge key elsewhere in the document",
			bundle: `
base: &b
  k: 1
also:
  <<: *b

metadata: []

policies:
  - name: plain
    rules:
      - when: "true"
        action: deny
        reason: r
`,
			wantCodes: []string{"yaml-merge-key", "bundle-error"},
			wantText:  []string{"line 7: cannot unmarshal"},
		},
		{
			name: "a policy list inherited through an alias holding a policy with no rules",
			bundle: `
base: &b
  - name: inherited

policies: *b
`,
			wantCodes: []string{"yaml-anchor", "bundle-error"},
			wantText:  []string{policyNeedsRuleMessage},
		},
		{
			name: "the same bundle shape without any reference",
			bundle: `
metadata: []

policies:
  - name: plain
    rules:
      - when: "true"
        action: deny
        reason: r
`,
			wantCodes: []string{"bundle-error"},
			wantText:  []string{"line 2: cannot unmarshal"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, err := ValidateBundle(tc.bundle, ValidateOptions{Source: "bundle.yaml"})
			if err != nil {
				t.Fatalf("ValidateBundle: %v", err)
			}
			for _, want := range tc.wantCodes {
				if !slices.ContainsFunc(issues, func(i Issue) bool { return i.Code == want }) {
					t.Fatalf("expected an issue with code %q, got %v", want, issues)
				}
			}
			var reported strings.Builder
			for _, issue := range issues {
				reported.WriteString(issue.Message)
				reported.WriteString("\n")
			}
			for _, want := range tc.wantText {
				if !strings.Contains(reported.String(), want) {
					t.Fatalf("expected the report to mention %q, got %v", want, issues)
				}
			}
			for _, issue := range issues {
				if issue.Line <= 0 {
					t.Fatalf("issue %v should name the line it is on", issue)
				}
			}
		})
	}
}

// TestValidateBundleReadsPoliciesSuppliedByAMergeKey pins the one case where a
// missing policies key is not missing: a root merge key supplies it. The merge
// key is refused, and saying the list is absent as well would name a mistake the
// author did not make.
func TestValidateBundleReadsPoliciesSuppliedByAMergeKey(t *testing.T) {
	bundle := `
defaults: &defaults
  policies:
    - name: inherited
      rules:
        - when: "true"
          action: deny
          reason: "r"

<<: *defaults
`
	issues, err := ValidateBundle(bundle, ValidateOptions{Source: "bundle.yaml"})
	if err != nil {
		t.Fatalf("ValidateBundle: %v", err)
	}
	for _, issue := range issues {
		if issue.Code == "missing-policies" {
			t.Fatalf("a merged policies list is not missing: %v", issues)
		}
	}
	if !slices.ContainsFunc(issues, func(i Issue) bool { return i.Code == "yaml-merge-key" }) {
		t.Fatalf("expected the merge key to be reported, got %v", issues)
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

// TestRewritingTagsRejectedAtEveryPosition pins the refusal of a YAML tag that
// makes a scalar's value differ from its written text, in each field where the
// two readers of a bundle would otherwise disagree about it. The walk judges the
// text and the decoder reads the value, so before this an `action: !!binary
// ZGVueQ==` linted as an invalid action and compiled as deny.
//
// Each case asserts both readers, since a construct only one of them refuses is
// the divergence this closes.
func TestRewritingTagsRejectedAtEveryPosition(t *testing.T) {
	cases := []struct {
		name   string
		bundle string
	}{
		{
			name: "a rule action",
			bundle: `
policies:
  - name: tagged-action
    rules:
      - when: "true"
        action: !!binary ZGVueQ==
        reason: "r"
`,
		},
		{
			name: "a rule condition",
			bundle: `
policies:
  - name: tagged-when
    rules:
      - when: !!binary MTwy
        action: deny
        reason: "r"
`,
		},
		{
			name: "the execution mode",
			bundle: `
policies:
  - name: tagged-mode
    mode: !!binary YWR2aXNvcnk=
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
		},
		{
			name: "an entrypoint list item",
			bundle: `
policies:
  - name: tagged-entrypoint
    entrypoints: [!!binary c2Nhbl92dWxuZXJhYmlsaXR5]
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
		},
		{
			name: "the policy name",
			bundle: `
policies:
  - name: !!binary dGFnZ2VkLW5hbWU=
    rules:
      - when: "true"
        action: deny
        reason: "r"
`,
		},
		{
			name: "a var name",
			bundle: `
policies:
  - name: tagged-var-name
    vars:
      ? !!binary YmxvY2tlZA==
      : '["left-pad"]'
    rules:
      - when: "pkg.name in blocked"
        action: deny
        reason: "r"
`,
		},
		{
			name: "a rule reason",
			bundle: `
policies:
  - name: tagged-reason
    rules:
      - when: "true"
        action: deny
        reason: !!binary cg==
`,
		},
		{
			name:   "the policies key itself",
			bundle: "!!binary cG9saWNpZXM=:\n  - name: tagged-key\n    rules:\n      - when: \"true\"\n        action: deny\n        reason: \"r\"\n",
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
			if !slices.Contains(codes, "yaml-opaque-scalar") {
				t.Fatalf("expected issue code %q, got %v: %v", "yaml-opaque-scalar", codes, issues)
			}
			for _, issue := range issues {
				if issue.Line <= 0 {
					t.Fatalf("issue %v should name the line the construct is on", issue)
				}
			}

			// The loader has to refuse the same document, or a bundle that lints as
			// broken would still compile, which is how a tagged action got in.
			_, loadErr := ParseStructuredSources([]byte(tc.bundle), "bundle.yaml")
			if loadErr == nil {
				t.Fatal("expected the loader to reject the bundle too")
			}
			if !strings.Contains(loadErr.Error(), opaqueScalarNotSupported) {
				t.Fatalf("loader error %q should refuse the construct by name", loadErr)
			}
		})
	}
}

// TestPlainScalarSpellingsStayAccepted pins the other side of the tag refusal:
// it keys off a scalar whose value is not its text, not off a tag, so every way
// an author writes a value plainly still loads. Quoting is the alternative the
// refusal points at, so quoting must not itself be refused.
func TestPlainScalarSpellingsStayAccepted(t *testing.T) {
	cases := []struct {
		name   string
		bundle string
	}{
		{
			name: "plain, quoted, and block scalars",
			bundle: `
policies:
  - name: plain-spellings
    description: >-
      folded
    mode: 'advisory'
    rules:
      - when: "true"
        action: "deny"
        reason: |
          multi
          line
`,
		},
		{
			name: "a tag that leaves the text alone",
			bundle: `
policies:
  - name: explicit-str
    rules:
      - when: "true"
        action: !!str deny
        reason: "r"
`,
		},
		{
			name: "an explicitly null optional field",
			bundle: `
policies:
  - name: null-mode
    mode: ~
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
			for _, issue := range issues {
				if issue.Severity != IssueHint {
					t.Fatalf("expected no problems, got %v", issue)
				}
			}
			if _, err := ParseStructuredSources([]byte(tc.bundle), "bundle.yaml"); err != nil {
				t.Fatalf("loader rejected a plainly written bundle: %v", err)
			}
		})
	}
}
