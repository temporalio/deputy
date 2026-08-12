package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/google/cel-go/cel"
	celast "github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/parser"
)

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
			if sources[0].Metadata.Name == "" {
				t.Fatalf("metadata missing from source: %+v", sources[0])
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

// isOptionalProducing reports whether expr syntactically yields a CEL optional
// value and is therefore a legal receiver for .orValue(). The accepted set is
// what the shipped corpus legitimately contains plus the unambiguous optional
// constructors, matched against cel-go's parsed representation:
//
//   - an optional field select such as jwt.?sub (the "_?._" call)
//   - an optional index such as m[?k] (the "_[?_]" call)
//   - optional.of / optional.ofNonZeroValue / optional.none, which parse as
//     member calls on the bare identifier "optional"
//   - a member .or() call whose receiver is optional, since or() stays optional
//   - a plain field select on an optional operand, since selection propagates
//     optionality (vulnerability.?package.direct)
//
// Everything else (a plain identifier, an unguarded select, a comprehension
// result such as filter(...), a non-optional call) does not produce an
// optional, so .orValue() on it is a violation. If a new legitimate optional
// producer ever enters the corpus (for example plain indexing into an
// optional), extend this set deliberately rather than loosening the check.
func isOptionalProducing(expr celast.Expr) bool {
	switch expr.Kind() {
	case celast.CallKind:
		call := expr.AsCall()
		switch call.FunctionName() {
		case "_?._", "_[?_]":
			return true
		case "or":
			return call.IsMemberFunction() && isOptionalProducing(call.Target())
		case "of", "ofNonZeroValue", "none":
			return call.IsMemberFunction() &&
				call.Target().Kind() == celast.IdentKind &&
				call.Target().AsIdent() == "optional"
		}
		return false
	case celast.SelectKind:
		sel := expr.AsSelect()
		return !sel.IsTestOnly() && isOptionalProducing(sel.Operand())
	default:
		return false
	}
}

// orValueViolations parses body with the same environment options the engine
// compiles policies with (optional syntax, macros, extension libraries) and
// returns the source text of every .orValue() receiver that is not
// optional-producing per isOptionalProducing.
//
// It walks the parsed AST rather than the checked one on purpose: the property
// is purely syntactic, the pinned checker accepts the broken form on dyn
// receivers (so checking adds no signal), and some broken shapes fail the
// checker outright, which would bury the precise violation under an unrelated
// type error.
func orValueViolations(t *testing.T, body string) []string {
	t.Helper()
	env, err := envWithNames(nil)
	if err != nil {
		t.Fatalf("build CEL env: %v", err)
	}
	// Macro call tracking only affects source metadata; it lets the unparser
	// render a comprehension back as the filter/exists/map call the author
	// wrote instead of failing on the expanded loop.
	env, err = env.Extend(cel.EnableMacroCallTracking())
	if err != nil {
		t.Fatalf("extend CEL env: %v", err)
	}
	parsed, iss := env.Parse(body)
	if iss != nil && iss.Err() != nil {
		t.Fatalf("parse policy: %v", iss.Err())
	}
	rep := parsed.NativeRep()
	var violations []string
	celast.PreOrderVisit(rep.Expr(), celast.NewExprVisitor(func(e celast.Expr) {
		if e.Kind() != celast.CallKind {
			return
		}
		call := e.AsCall()
		if call.FunctionName() != "orValue" || !call.IsMemberFunction() {
			return
		}
		if isOptionalProducing(call.Target()) {
			return
		}
		receiver, err := parser.Unparse(call.Target(), rep.SourceInfo())
		if err != nil {
			receiver = fmt.Sprintf("(unrenderable expression, kind %d)", call.Target().Kind())
		}
		violations = append(violations, receiver)
	}))
	return violations
}

// TestNoOrValueOnNonOptional pins the rule that .orValue() may only be applied
// to an expression that actually produces a CEL optional.
//
// Applying it to anything else is a silent no-op, not a default: through
// cel-go v0.26 the runtime handed the receiver back without ever evaluating
// the argument, and it does not rescue an unbound variable either, because
// attribute resolution fails before the call. cel-go v0.28 turned the same
// expression into "no such overload", which broke all three CI gates at once.
//
// Neither a compile check nor an eval check catches this on the pinned
// version, since the bad form both compiles and evaluates there. A static
// check is the only thing that holds across cel-go versions, so this test
// walks the parsed AST of every shipped policy (after structured-YAML
// expansion, the same source the engine evaluates) and classifies every
// .orValue() receiver. The detector subtests prove the walk both fires on the
// broken shapes and stays quiet on legitimate ones.
func TestNoOrValueOnNonOptional(t *testing.T) {
	t.Parallel()
	for _, path := range shippedPolicyPaths(t) {
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			sources, err := LoadSources([]string{path})
			if err != nil {
				t.Fatalf("LoadSources(%s): %v", path, err)
			}
			for _, src := range sources {
				for _, receiver := range orValueViolations(t, src.Body) {
					t.Errorf("%s: .orValue() applied to non-optional receiver %q; "+
						"guard the hop that can actually be absent (x.?y.orValue(z)) or drop the call",
						src.Name, receiver)
				}
			}
		})
	}
	t.Run("detector", func(t *testing.T) {
		t.Parallel()
		// The corpus above only proves the absence of false positives. These
		// scratch bundles, expanded through the same structured-YAML path as
		// shipped policies, prove the detector fires on the broken shapes,
		// including the nested-lambda shape a line-based scan cannot separate
		// from its surroundings, and stays quiet on a guarded chain reflowed
		// across lines.
		tests := []struct {
			name          string
			when          string
			wantReceivers []string
		}{
			{
				name:          "plain variable receiver is flagged",
				when:          `size(vulnerabilities.orValue([])) > 0`,
				wantReceivers: []string{"vulnerabilities"},
			},
			{
				name: "inner guarded lambda does not vouch for outer comprehension",
				when: `changesList.filter(c, c.?type.orValue("").lowerAscii() == "added").orValue([]) == []`,
				wantReceivers: []string{
					`changesList.filter(c, c.?type.orValue("").lowerAscii() == "added")`,
				},
			},
			{
				name:          "ternary receiver is flagged",
				when:          `size((change.added ? packages : changes).orValue([])) > 0`,
				wantReceivers: []string{`change.added ? packages : changes`},
			},
			{
				name:          "plain call with an optional argument is flagged",
				when:          `size(base64.decode(config.?registry.orValue("")).orValue(b"")) > 0`,
				wantReceivers: []string{`base64.decode(config.?registry.orValue(""))`},
			},
			{
				name:          "string literal containing a question mark is flagged",
				when:          `size(config["?"].orValue([])) > 0`,
				wantReceivers: []string{`config["?"]`},
			},
			{
				name:          "chained orValue on an already defaulted value is flagged",
				when:          `jwt.?sub.orValue("").orValue("fallback") == ""`,
				wantReceivers: []string{`jwt.?sub.orValue("")`},
			},
			{
				name: "guarded chain reflowed across lines passes",
				when: "jwt.?sub\n          .orValue(\"\") == \"\"",
			},
			{
				name: "optional index and or-chain pass",
				when: `config[?"registry"].or(optional.of("default")).orValue("") == ""`,
			},
			{
				name: "select through optional passes",
				when: `vulnerability.?package.direct.orValue(false)`,
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()
				bundleYAML := fmt.Sprintf("policies:\n  - name: scratch\n    rules:\n      - action: deny\n        when: %s\n", strconv.Quote(test.when))
				sources, err := ParseStructuredSources([]byte(bundleYAML), "scratch.yaml")
				if err != nil {
					t.Fatalf("ParseStructuredSources: %v", err)
				}
				var got []string
				for _, src := range sources {
					got = append(got, orValueViolations(t, src.Body)...)
				}
				if !slices.Equal(got, test.wantReceivers) {
					t.Errorf("orValueViolations() = %q, want %q", got, test.wantReceivers)
				}
			})
		}
	})
}
