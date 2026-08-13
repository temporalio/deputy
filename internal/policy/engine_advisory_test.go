package policy

import (
	"strings"
	"testing"
)

func TestEngineAdvisoryDowngradesDeny(t *testing.T) {
	src := Source{
		Name: "advisory",
		Body: `//! policy.name = "adv"
//! policy.mode = "advisory"
true ? [{"action":"deny","reason":"block it"}] : []`,
	}
	eng, err := NewEngine([]Source{src})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	actions, err := eng.EvaluateAll(t.Context(), nil, "proxy", "")
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].Type != "warn" {
		t.Fatalf("expected warn, got %s", actions[0].Type)
	}
	if actions[0].Status != nil {
		t.Fatalf("expected status to be nil after downgrade, got %v", *actions[0].Status)
	}
	if actions[0].Reason == "" {
		t.Fatalf("expected reason to be preserved")
	}
}

// TestEngineRefusesAnUnknownMode pins that a policy declaring a mode Deputy does
// not recognize is refused when it is loaded, on every path a mode can arrive by.
// Evaluation asks whether the mode is advisory and enforces when it is not, so a
// misspelled "advsiory" turns a policy the author meant to observe with into one
// that blocks: the opposite of what they asked for, and silent. The engine already
// refuses an unknown entrypoint at this boundary, and a mode is the same kind of
// closed vocabulary.
//
// An absent mode is not an unknown one. It means enforce, which is the default, so
// it has to keep loading.
func TestEngineRefusesAnUnknownMode(t *testing.T) {
	const rule = "\ntrue ? [{\"action\":\"deny\",\"reason\":\"block it\"}] : []"
	cases := []struct {
		name     string
		metadata string
		wantErr  string
		wantType string
	}{
		{
			name:     "a misspelled mode",
			metadata: "//! policy.mode = \"advsiory\"",
			wantErr:  `invalid mode "advsiory"`,
		},
		{
			name:     "a mode that is not in the vocabulary at all",
			metadata: "//! policy.mode = \"audit\"",
			wantErr:  `invalid mode "audit"`,
		},
		{
			name:     "no mode at all",
			metadata: "//! policy.name = \"plain\"",
			wantType: ActionDeny,
		},
		{
			name:     "an advisory mode written with padding and capitals",
			metadata: "//! policy.mode = \"  ADVISORY  \"",
			wantType: ActionWarn,
		},
		{
			name:     "an enforce mode",
			metadata: "//! policy.mode = \"enforce\"",
			wantType: ActionDeny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := Source{Name: "mode", Body: tc.metadata + rule}
			eng, err := NewEngine([]Source{src})
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected the mode to be refused, got engine %v", eng)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q should name the offending mode as %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			actions, err := eng.EvaluateAll(t.Context(), nil, "proxy", "")
			if err != nil {
				t.Fatalf("EvaluateAll: %v", err)
			}
			if len(actions) != 1 || actions[0].Type != tc.wantType {
				t.Fatalf("expected one %s action, got %+v", tc.wantType, actions)
			}
		})
	}
}

func TestStructuredPolicyModeAdvisory(t *testing.T) {
	yaml := `policies:
  - name: adv-mode
    mode: advisory
    rules:
      - action: deny
        when: true
        reason: nope
`
	sources, ok, err := tryParseStructuredBundle([]byte(yaml), "inline")
	if err != nil || !ok {
		t.Fatalf("parse structured: %v ok=%v", err, ok)
	}
	eng, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	acts, err := eng.EvaluateAll(t.Context(), nil, "scan", "scan_report")
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if len(acts) != 1 || acts[0].Type != "warn" {
		t.Fatalf("expected warn, got %+v", acts)
	}
}

// TestValidateSourceMetadataAgreesWithNewEngine pins the equivalence a reader that
// checks a source without running it depends on: ValidateSourceMetadata accepts a
// source exactly when NewEngine will not reject it over its metadata, with the same
// wording.
//
// Lint is that reader. A compiled bundle carries its policies as compiled CEL with
// their metadata in `//!` comments, so compiling the CEL used to be the only question
// lint asked of one, and a bundle declaring `advsiory` reported OK and then failed to
// load in production. Both readers now go through one function, and this is what
// keeps a check added to the engine boundary from being a check lint does not make.
func TestValidateSourceMetadataAgreesWithNewEngine(t *testing.T) {
	// Every body compiles, so the only thing either reader can object to is the
	// metadata above it.
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "a misspelled mode",
			body:    "//! policy.mode = advsiory\n[]",
			wantErr: `invalid mode "advsiory"`,
		},
		{
			name:    "a mode outside the vocabulary",
			body:    "//! policy.mode = \"audit\"\n[]",
			wantErr: `invalid mode "audit"`,
		},
		{
			name:    "a misspelled entrypoint",
			body:    "//! policy.entrypoints = \"scan_vulnerabilities\"\n[]",
			wantErr: `invalid entrypoint "scan_vulnerabilities"`,
		},
		{name: "no metadata at all", body: "[]"},
		{name: "an advisory mode", body: "//! policy.mode = \"advisory\"\n[]"},
		{name: "an enforce mode", body: "//! policy.mode = \"enforce\"\n[]"},
		{name: "a known entrypoint", body: "//! policy.entrypoints = \"scan_vulnerability\"\n[]"},
		{name: "a name and a description only", body: "//! policy.name = \"p\"\n//! policy.description = \"d\"\n[]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := Source{Name: "b.json::p", Body: tc.body}
			// The body compiling is what makes this a question about metadata: a
			// reader that stopped at the CEL would agree by accident otherwise.
			if err := Compile(src.Body, nil); err != nil {
				t.Fatalf("the body should compile, so the metadata is the only thing left to refuse: %v", err)
			}
			validateErr := ValidateSourceMetadata(src)
			_, engineErr := NewEngine([]Source{src})
			if (validateErr == nil) != (engineErr == nil) {
				t.Fatalf("the two readers disagree: ValidateSourceMetadata=%v, NewEngine=%v", validateErr, engineErr)
			}
			if tc.wantErr == "" {
				if validateErr != nil {
					t.Fatalf("expected the source to be accepted, got %v", validateErr)
				}
				return
			}
			if !strings.Contains(validateErr.Error(), tc.wantErr) {
				t.Fatalf("error %q should name the offending value as %q", validateErr, tc.wantErr)
			}
			if validateErr.Error() != engineErr.Error() {
				t.Fatalf("the two readers word one refusal differently: %q and %q", validateErr, engineErr)
			}
			if !strings.Contains(validateErr.Error(), src.Name) {
				t.Fatalf("error %q should name the policy it refuses", validateErr)
			}
		})
	}
}
