package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/inventory"
	"github.com/temporalio/deputy/internal/policy"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/repository/workspace"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
)

// dependencyPackage aliases the proto package type the inventory path produces,
// keeping the helper signatures below readable.
type dependencyPackage = dependencyv1.Package

// TestPolicyMatchesCanonicalEcosystemFromRealInventory drives the real
// construction path (filesystem extraction -> proto conversion -> policy
// payload) and pins the canonical contract: a policy written against the
// canonical token matches a package whose scanner-emitted ecosystem is a
// display name such as "Go" or "GitHub Actions".
//
// Before ecosystem canonicalization these cases were silently dead: the rules
// compiled, ran, and never fired because pkg.ecosystem carried "Go".
func TestPolicyMatchesCanonicalEcosystemFromRealInventory(t *testing.T) {
	pkgs := scanFixtureWorkspace(t)

	tests := []struct {
		name        string
		displayName string // ecosystem spelling inventory actually emits
		token       string // canonical token a policy author writes
	}{
		{name: "go module", displayName: "Go", token: "go"},
		{name: "github action", displayName: "GitHub Actions", token: "github-actions"},
		{name: "dockerfile base image", displayName: "docker", token: "docker"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := findPackageByEcosystem(pkgs, tt.displayName)
			if pkg == nil {
				t.Fatalf("fixture produced no package with ecosystem %q (got %v)", tt.displayName, ecosystemsOf(pkgs))
			}

			bundle := []byte(`policies:
  - name: canonical-ecosystem
    ecosystems: ["` + tt.token + `"]
    rules:
      - action: deny
        when: pkg.ecosystem == "` + tt.token + `"
        reason: matched
`)
			sources, err := policy.ParseStructuredSources(bundle, "canonical.yaml")
			if err != nil {
				t.Fatalf("ParseStructuredSources: %v", err)
			}

			actions, err := policy.EvaluateMap(t.Context(), sources, map[string]any{"pkg": pkg})
			if err != nil {
				t.Fatalf("EvaluateMap: %v", err)
			}
			if len(actions) != 1 || actions[0].Type != policy.ActionDeny {
				t.Fatalf("policy on canonical token %q did not match package %s (raw ecosystem %q): actions=%v",
					tt.token, pkg.GetName(), pkg.GetEcosystem(), actions)
			}
		})
	}
}

// TestDisplayCasedPolicyNoLongerMatches records the intended behavior change:
// a policy written against the display name stops matching once policy inputs
// are canonicalized.
func TestDisplayCasedPolicyNoLongerMatches(t *testing.T) {
	pkgs := scanFixtureWorkspace(t)
	pkg := findPackageByEcosystem(pkgs, "Go")
	if pkg == nil {
		t.Fatalf("fixture produced no Go package (got %v)", ecosystemsOf(pkgs))
	}

	sources, err := policy.ParseStructuredSources([]byte(`policies:
  - name: display-cased
    rules:
      - action: deny
        when: pkg.ecosystem == "Go"
        reason: matched
`), "display.yaml")
	if err != nil {
		t.Fatalf("ParseStructuredSources: %v", err)
	}

	actions, err := policy.EvaluateMap(t.Context(), sources, map[string]any{"pkg": pkg})
	if err != nil {
		t.Fatalf("EvaluateMap: %v", err)
	}
	if len(actions) != 0 {
		t.Fatalf(`pkg.ecosystem == "Go" still matched after canonicalization: %v`, actions)
	}
}

// TestShippedPolicyFiresOnRealDiffPath drives the real diff construction path
// (inventory of two trees -> compare -> proto change -> policy payload) against
// the shipped deny-aws-sdk-v1 example. The example asks for ecosystem "go" and a
// version matching "^v1\.", and before identity normalization the diff path
// handed policies "Go" and "1.44.0", so the rule never fired.
func TestShippedPolicyFiresOnRealDiffPath(t *testing.T) {
	basePkgs := scanGoModule(t, "module example.com/demo\n\ngo 1.24\n")
	targetPkgs := scanGoModule(t, "module example.com/demo\n\ngo 1.24\n\nrequire github.com/aws/aws-sdk-go v1.44.0\n")

	changes := compare.ComparePackages(basePkgs, targetPkgs, nil, nil, nil)
	protoChanges := internalproto.PackageChangesToProto(changes)
	if len(protoChanges) != 1 {
		t.Fatalf("expected exactly one dependency change, got %d: %v", len(protoChanges), changes)
	}
	change := protoChanges[0]
	if got := change.GetPackage().GetEcosystem(); got != "Go" {
		t.Fatalf("fixture precondition: raw ecosystem = %q, want the display form %q", got, "Go")
	}
	if got := change.GetPackage().GetVersion(); got != "1.44.0" {
		t.Fatalf("fixture precondition: raw version = %q, want the unprefixed form %q", got, "1.44.0")
	}

	sources, err := policy.LoadSources([]string{filepath.Join("..", "..", "policy", "examples", "deny-aws-sdk-v1.yaml")})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}

	payload := map[string]any{
		"change": change,
		"pkg":    change.GetPackage(),
	}
	actions, err := policy.EvaluateMap(t.Context(), sources, payload)
	if err != nil {
		t.Fatalf("EvaluateMap: %v", err)
	}
	if len(actions) != 1 || actions[0].Type != policy.ActionDeny {
		t.Fatalf("deny-aws-sdk-v1 did not fire on the diff path for %s@%s (%s): actions=%v",
			change.GetPackage().GetName(), change.GetPackage().GetVersion(), change.GetPackage().GetEcosystem(), actions)
	}
}

// scanGoModule inventories a temporary module with the given go.mod contents.
func scanGoModule(t *testing.T, gomod string) []*extractor.Package {
	t.Helper()

	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "go.mod"), gomod)

	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace.NewDir: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	pkgs, err := inventory.ScanPackagesWorking(t.Context(), ws, inventory.ScanOptions{})
	if err != nil {
		t.Fatalf("ScanPackagesWorking: %v", err)
	}
	return pkgs
}

// scanFixtureWorkspace inventories a temporary project that exercises three
// ecosystem spellings at once: a Go module ("Go"), a workflow action
// ("GitHub Actions", the display name with a space), and a Dockerfile base
// image ("docker", already lowercase).
func scanFixtureWorkspace(t *testing.T) []*dependencyPackage {
	t.Helper()

	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "go.mod"), `module example.com/fixture

go 1.24

require github.com/google/uuid v1.6.0
`)
	writeFixture(t, filepath.Join(dir, ".github", "workflows", "ci.yml"), `name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`)
	writeFixture(t, filepath.Join(dir, "Dockerfile"), "FROM alpine:3.19\nRUN echo hi\n")

	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace.NewDir: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	extracted, err := inventory.ScanPackagesWorking(t.Context(), ws, inventory.ScanOptions{})
	if err != nil {
		t.Fatalf("ScanPackagesWorking: %v", err)
	}
	pkgs := internalproto.ExtractorPackagesToProto(extracted, nil)
	if len(pkgs) == 0 {
		t.Fatal("fixture workspace produced no packages")
	}
	return pkgs
}

// writeFixture writes a fixture file, creating parent directories as needed.
func writeFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// findPackageByEcosystem returns the first package whose raw ecosystem matches
// name exactly, so a test can assert on the spelling inventory really emits.
func findPackageByEcosystem(pkgs []*dependencyPackage, name string) *dependencyPackage {
	for _, pkg := range pkgs {
		if pkg.GetEcosystem() == name {
			return pkg
		}
	}
	return nil
}

// ecosystemsOf lists the distinct raw ecosystem spellings in pkgs for failure
// messages.
func ecosystemsOf(pkgs []*dependencyPackage) []string {
	seen := map[string]bool{}
	var out []string
	for _, pkg := range pkgs {
		if eco := pkg.GetEcosystem(); !seen[eco] {
			seen[eco] = true
			out = append(out, eco)
		}
	}
	return out
}
