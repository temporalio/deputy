package policy

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestOrderedVarsExpandInAuthorOrder(t *testing.T) {
	p := structuredPolicy{
		Name: "ordered-vars",
		Vars: orderedVars{
			{Name: "a", Value: "1", IsString: true},
			{Name: "b", Value: "a + 1", IsString: true},
			{Name: "c", Value: "b + 1", IsString: true},
			{Name: "literalList", Value: []any{"x", "y"}, IsString: false},
			{Name: "literalMap", Value: map[string]any{"k": "v"}, IsString: false},
		},
		Rules: []structuredRule{
			{Action: "deny", When: "c == 3 && literalList.size() == 2 && literalMap.k == \"v\""},
		},
	}
	body, err := p.toCELSource()
	if err != nil {
		t.Fatalf("toCELSource: %v", err)
	}
	// Verify ordering cues are present in the expanded CEL.
	if !(strings.Contains(body, "map(a") && strings.Contains(body, "map(b") && strings.Contains(body, "map(c")) {
		t.Fatalf("expanded body missing vars: %s", body)
	}
	if err := Compile(body, nil); err != nil {
		t.Fatalf("compiled source invalid: %v", err)
	}
}

func TestLiteralsNestedListsAndMapsEvaluate(t *testing.T) {
	p := structuredPolicy{
		Name: "nested-literals",
		Vars: orderedVars{
			{Name: "listMaps", Value: []any{map[string]any{"k": "v"}}, IsString: false},
			{Name: "listLists", Value: []any{[]any{"a", "b"}, []any{"c"}}, IsString: false},
		},
		Rules: []structuredRule{
			{
				Action: "deny",
				When:   `listMaps[0].k == "v" && listLists.size() == 2 && listLists[0].size() == 2`,
				Reason: "nested literals ok",
			},
		},
	}
	src, err := p.toCELSource()
	if err != nil {
		t.Fatalf("toCELSource: %v", err)
	}
	val, err := Evaluate(t.Context(), src, nil)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	actions, ok := val.([]any)
	if !ok || len(actions) != 1 {
		t.Fatalf("expected one action, got %#v", val)
	}
	act, _ := actions[0].(map[string]any)
	if act["action"] != "deny" {
		t.Fatalf("expected deny action, got %+v", act)
	}
}

func TestOrderedVarsRejectDuplicateNames(t *testing.T) {
	p := structuredPolicy{
		Name: "dupe-vars",
		Vars: orderedVars{
			{Name: "a", Value: "1", IsString: true},
			{Name: "a", Value: "2", IsString: true},
		},
		Rules: []structuredRule{{Action: "deny", When: "true"}},
	}
	if _, err := p.toCELSource(); err == nil {
		t.Fatalf("expected error for duplicate var names, got nil")
	}
}

// TestLoaderNormalizesVarNames pins that the loader reads a variable name the
// way validation and CEL do, with surrounding whitespace trimmed. CEL binds
// " blocked " and "blocked" as the one identifier, so a bundle declaring both
// shadows one with the other; validation calls that a duplicate, and a loader
// that compared the raw spellings would compile a bundle the linter rejects.
func TestLoaderNormalizesVarNames(t *testing.T) {
	cases := []struct {
		name       string
		vars       string
		wantErr    string
		wantInBody string
	}{
		{
			name:       "a padded name binds the trimmed identifier",
			vars:       "      \" blocked \": '[\"left-pad\"]'\n",
			wantInBody: ".map(blocked,",
		},
		{
			name:    "a padded name duplicating a bare one is rejected",
			vars:    "      blocked: '[\"left-pad\"]'\n      \" blocked \": '[\"right-pad\"]'\n",
			wantErr: `duplicate var name "blocked"`,
		},
		{
			name:    "a name that is only whitespace is rejected",
			vars:    "      \"  \": '1'\n",
			wantErr: "vars must have non-empty names",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bundle := "policies:\n  - name: vars\n    vars:\n" + tc.vars +
				"    rules:\n      - when: \"true\"\n        action: deny\n        reason: r\n"
			sources, err := ParseStructuredSources([]byte(bundle), "bundle.yaml")
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got sources %+v", tc.wantErr, sources)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q missing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseStructuredSources: %v", err)
			}
			if len(sources) != 1 {
				t.Fatalf("expected one source, got %d", len(sources))
			}
			if !strings.Contains(sources[0].Body, tc.wantInBody) {
				t.Fatalf("body %q missing %q", sources[0].Body, tc.wantInBody)
			}
		})
	}
}

// TestStructuredPolicyValidatesActionVocabulary pins that a rule action outside
// the allow/deny/warn vocabulary is a load-time error, and that casing and
// surrounding whitespace are normalized rather than rejected.
func TestStructuredPolicyValidatesActionVocabulary(t *testing.T) {
	cases := []struct {
		name        string
		action      string
		wantErr     bool
		wantInError []string
		wantEmitted string
	}{
		{name: "deny", action: "deny", wantEmitted: "deny"},
		{name: "warn", action: "warn", wantEmitted: "warn"},
		{name: "allow", action: "allow", wantEmitted: "allow"},
		{name: "uppercase is normalized", action: "DENY", wantEmitted: "deny"},
		{name: "padded is normalized", action: "  Warn\t", wantEmitted: "warn"},
		{
			name:        "typo is rejected",
			action:      "dney",
			wantErr:     true,
			wantInError: []string{`"dney"`, "allow|deny|warn"},
		},
		{
			name:        "unknown verb is rejected",
			action:      "block",
			wantErr:     true,
			wantInError: []string{`"block"`, "allow|deny|warn"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := structuredPolicy{
				Name:  "vocabulary",
				Rules: []structuredRule{{Action: tc.action, When: "true", Reason: "because"}},
			}
			src, err := p.toCELSource()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for action %q, got source: %s", tc.action, src)
				}
				for _, want := range append(tc.wantInError, "rule[0]") {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error %q missing %q", err, want)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("toCELSource: %v", err)
			}
			if !strings.Contains(src, fmt.Sprintf(`"action":"%s"`, tc.wantEmitted)) {
				t.Fatalf("expected normalized action %q in source: %s", tc.wantEmitted, src)
			}
		})
	}
}

// TestStructuredBundleActionErrorNamesPolicyAndFile pins that the parse error for
// an unknown action identifies the file, policy, and rule the author must fix.
func TestStructuredBundleActionErrorNamesPolicyAndFile(t *testing.T) {
	data := []byte(`
policies:
  - name: typo-action
    rules:
      - when: "true"
        action: dney
        reason: "should deny"
`)
	_, err := ParseStructuredSources(data, "bundle.yaml")
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
	for _, want := range []string{"bundle.yaml", "typo-action", "rule[0]", `"dney"`, "allow|deny|warn"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %q", err, want)
		}
	}
}

func TestStructuredPolicyNormalizesCommandAliases(t *testing.T) {
	p := structuredPolicy{
		Name:     "sandbox-command",
		Commands: []string{"exec", "sandbox"},
		Rules:    []structuredRule{{Action: "deny", When: "true"}},
	}
	src, err := p.toCELSource()
	if err != nil {
		t.Fatalf("toCELSource: %v", err)
	}
	if !strings.Contains(src, `//! policy.commands = "sandbox"`) {
		t.Fatalf("compiled source did not use canonical sandbox command: %s", src)
	}
	if strings.Contains(src, "exec") {
		t.Fatalf("compiled source retained legacy exec alias: %s", src)
	}
}

// TestGeneratedEcosystemGuardCannotBeRewritten pins that a policy's ecosystems
// reach the generated guard as string literals and nothing else. The guard is CEL
// source built by interpolating each value, so a value carrying a quote used to
// close the list and continue the expression: the bundle below reads as scoped to
// npm, and before this it compiled, linted clean, and denied a PyPI package. The
// text a reviewer reads has to be the policy that runs, which is the same reason
// the format refuses aliases.
//
// The plain cases are here too, so escaping cannot pass by scoping nothing.
func TestGeneratedEcosystemGuardCannotBeRewritten(t *testing.T) {
	cases := []struct {
		name       string
		ecosystems string
		ecosystem  string
		wantDeny   bool
	}{
		{
			name:       "a value crafted to close the list and always match",
			ecosystems: `['npm"] || true || ["x"] == ["x']`,
			ecosystem:  "PyPI",
		},
		{
			name:       "a value carrying a bare quote",
			ecosystems: `['npm"']`,
			ecosystem:  "npm",
		},
		{
			name:       "a value carrying a backslash",
			ecosystems: `['npm\']`,
			ecosystem:  "npm",
		},
		{
			name:       "the declared ecosystem matches",
			ecosystems: `['npm']`,
			ecosystem:  "npm",
			wantDeny:   true,
		},
		{
			name:       "another ecosystem does not match",
			ecosystems: `['npm']`,
			ecosystem:  "PyPI",
		},
		{
			name:       "one of several declared ecosystems matches",
			ecosystems: `['npm', 'PyPI']`,
			ecosystem:  "PyPI",
			wantDeny:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bundle := "policies:\n  - name: scoped\n    ecosystems: " + tc.ecosystems +
				"\n    rules:\n      - when: \"pkg.name == 'left-pad'\"\n        action: deny\n        reason: r\n"
			sources, err := ParseStructuredSources([]byte(bundle), "b.yaml")
			if err != nil {
				t.Fatalf("ParseStructuredSources: %v", err)
			}
			eng, err := NewEngine(sources)
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			// request is supplied because the generated guard reads it before
			// pkg, and an absent one errors before the ecosystem is compared.
			payload := map[string]any{
				"pkg":     map[string]any{"name": "left-pad", "ecosystem": tc.ecosystem},
				"request": map[string]any{"ecosystem": "unrelated"},
			}
			actions, err := eng.EvaluateAllMap(t.Context(), payload, "scan", "")
			if err != nil {
				t.Fatalf("EvaluateAllMap: %v", err)
			}
			denied := slices.ContainsFunc(actions, func(a Action) bool { return ActionTypeIs(a.Type, ActionDeny) })
			if denied != tc.wantDeny {
				t.Fatalf("denied a %s package = %v, want %v (actions %+v)", tc.ecosystem, denied, tc.wantDeny, actions)
			}
		})
	}
}
