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
	if len(changes) != 1 {
		t.Fatalf("expected exactly one dependency change, got %d: %v", len(changes), changes)
	}
	change := changes[0]
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

// TestCratePolicyReadsThePublishedName drives the real construction path for a
// Rust project (Cargo.lock extraction -> proto conversion -> policy payload)
// and pins crate identity: a policy names a crate the way crates.io publishes
// it, hyphen and all. Folding the name into "async_trait" to make a comparison
// work would hand a policy author a spelling that appears on no registry, in no
// Cargo.toml, and in no advisory, so the folded rule must not match.
//
// The classification the fold used to serve is checked alongside it: the
// renamed entry (my-serde = { package = "serde" }) still resolves to a direct
// serde, which is the behavior that would regress if equivalence had been
// dropped rather than moved.
func TestCratePolicyReadsThePublishedName(t *testing.T) {
	pkgs := scanCargoProject(t)

	tests := []struct {
		name      string
		crateName string
		wantMatch bool
	}{
		{name: "published spelling matches", crateName: "async-trait", wantMatch: true},
		{name: "folded spelling does not", crateName: "async_trait", wantMatch: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := findPackageByName(pkgs, "async-trait")
			if pkg == nil {
				t.Fatalf("fixture produced no async-trait package (got %v)", namesOf(pkgs))
			}

			sources, err := policy.ParseStructuredSources([]byte(`policies:
  - name: crate-identity
    rules:
      - action: deny
        when: pkg.ecosystem == "cargo" && pkg.name == "`+tt.crateName+`"
        reason: matched
`), "crate.yaml")
			if err != nil {
				t.Fatalf("ParseStructuredSources: %v", err)
			}

			actions, err := policy.EvaluateMap(t.Context(), sources, map[string]any{"pkg": pkg})
			if err != nil {
				t.Fatalf("EvaluateMap: %v", err)
			}
			if matched := len(actions) == 1; matched != tt.wantMatch {
				t.Errorf("policy on %q matched=%v, want %v (policy saw name %q)",
					tt.crateName, matched, tt.wantMatch, pkg.GetName())
			}
		})
	}

	serde := findPackageByName(pkgs, "serde")
	if serde == nil {
		t.Fatalf("fixture produced no serde package (got %v)", namesOf(pkgs))
	}
	if !serde.GetDirect() {
		t.Error("serde is not direct: the renamed manifest entry stopped resolving to the crate it names")
	}
}

// TestOptionalDependencyPolicyReadsItAsDirect drives the real npm construction
// path (package.json plus package-lock.json extraction -> direct-dependency
// collection -> proto conversion -> policy payload) and pins what "direct" means
// for an optionalDependencies entry.
//
// npm installs an optional dependency like any other, the lockfile carries it,
// and the extractor reports it as an installed package; only a failed install is
// tolerated. Collecting direct dependencies read "dependencies" and
// "devDependencies" alone, so an explicitly declared optional package reached
// policies and the generated SBOM as direct=false and a direct-only rule skipped
// it. A lockfile entry nobody declared is checked alongside it, since the fix
// must not amount to marking everything installed direct.
func TestOptionalDependencyPolicyReadsItAsDirect(t *testing.T) {
	pkgs := scanNpmProject(t)

	tests := []struct {
		name       string
		pkgName    string
		wantDirect bool
	}{
		{name: "optional dependency is declared", pkgName: "fsevents", wantDirect: true},
		{name: "runtime dependency is declared", pkgName: "left-pad", wantDirect: true},
		{name: "lockfile entry nobody declared is not", pkgName: "tiny-dep", wantDirect: false},
	}

	sources, err := policy.ParseStructuredSources([]byte(`policies:
  - name: direct-npm-dependency
    ecosystems: ["npm"]
    rules:
      - action: deny
        when: pkg.ecosystem == "npm" && pkg.direct
        reason: matched
`), "direct.yaml")
	if err != nil {
		t.Fatalf("ParseStructuredSources: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := findPackageByName(pkgs, tt.pkgName)
			if pkg == nil {
				t.Fatalf("fixture produced no %q package (got %v)", tt.pkgName, namesOf(pkgs))
			}

			actions, err := policy.EvaluateMap(t.Context(), sources, map[string]any{"pkg": pkg})
			if err != nil {
				t.Fatalf("EvaluateMap: %v", err)
			}
			if matched := len(actions) == 1; matched != tt.wantDirect {
				t.Errorf("direct-dependency deny on %q matched=%v, want %v (policy saw direct=%v)",
					tt.pkgName, matched, tt.wantDirect, pkg.GetDirect())
			}
		})
	}
}

// scanNpmProject inventories a temporary npm project that declares one runtime
// dependency and one optional dependency, with a lockfile that also carries a
// package nothing declares.
func scanNpmProject(t *testing.T) []*dependencyPackage {
	t.Helper()

	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "package.json"), `{
  "name": "fixture",
  "version": "1.0.0",
  "dependencies": { "left-pad": "^1.3.0" },
  "optionalDependencies": { "fsevents": "^2.3.2" }
}
`)
	writeFixture(t, filepath.Join(dir, "package-lock.json"), `{
  "name": "fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "fixture",
      "version": "1.0.0",
      "dependencies": { "left-pad": "^1.3.0" },
      "optionalDependencies": { "fsevents": "^2.3.2" }
    },
    "node_modules/left-pad": { "version": "1.3.0" },
    "node_modules/fsevents": { "version": "2.3.2", "optional": true },
    "node_modules/tiny-dep": { "version": "0.1.0" }
  }
}
`)

	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace.NewDir: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	extracted, err := inventory.ScanPackagesWorking(t.Context(), ws, inventory.ScanOptions{})
	if err != nil {
		t.Fatalf("ScanPackagesWorking: %v", err)
	}
	direct := compare.CollectDirectDependenciesFromWorkspace(ws)
	pkgs := internalproto.ExtractorPackagesToProto(extracted, direct)
	if len(pkgs) == 0 {
		t.Fatal("npm fixture produced no packages")
	}
	return pkgs
}

// scanCargoProject inventories a temporary Rust project whose manifest renames
// one dependency (my-serde = { package = "serde" }) and declares another under
// a published hyphenated name, with a lockfile that spells both the way Cargo
// records them.
func scanCargoProject(t *testing.T) []*dependencyPackage {
	t.Helper()

	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "Cargo.toml"), `[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
my-serde = { package = "serde", version = "1.0.203" }
async-trait = "0.1.80"
`)
	writeFixture(t, filepath.Join(dir, "Cargo.lock"), `version = 3

[[package]]
name = "serde"
version = "1.0.203"

[[package]]
name = "async-trait"
version = "0.1.80"
`)

	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace.NewDir: %v", err)
	}
	t.Cleanup(func() { _ = ws.Close() })

	extracted, err := inventory.ScanPackagesWorking(t.Context(), ws, inventory.ScanOptions{})
	if err != nil {
		t.Fatalf("ScanPackagesWorking: %v", err)
	}
	direct := compare.CollectDirectDependenciesFromWorkspace(ws)
	pkgs := internalproto.ExtractorPackagesToProto(extracted, direct)
	if len(pkgs) == 0 {
		t.Fatal("cargo fixture produced no packages")
	}
	return pkgs
}

// findPackageByName returns the first package reported under name exactly, so a
// test can assert on the spelling inventory really emits.
func findPackageByName(pkgs []*dependencyPackage, name string) *dependencyPackage {
	for _, pkg := range pkgs {
		if pkg.GetName() == name {
			return pkg
		}
	}
	return nil
}

// namesOf lists the package names in pkgs for failure messages.
func namesOf(pkgs []*dependencyPackage) []string {
	out := make([]string, 0, len(pkgs))
	for _, pkg := range pkgs {
		out = append(out, pkg.GetName())
	}
	return out
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
