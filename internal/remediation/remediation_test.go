package remediation

import (
	"slices"
	"strings"
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/inventory"
	"github.com/temporalio/deputy/internal/vulnerability"
)

func TestCommandsFromConsolidatedGeneratesPlan(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:     "STD-1",
			Package:       "stdlib",
			Version:       "1.20.0",
			FixedVersions: []string{"1.21.0"},
		},
		{
			PrimaryID:     "GO-1",
			Package:       "github.com/acme/lib",
			Version:       "v1.0.0",
			FixedVersions: []string{"v1.1.0"},
			IsDirect:      true,
			ManifestRefs:  []dependencyv1.ManifestRef{{Manager: "go", Path: "./go.mod"}},
		},
		{
			PrimaryID:     "RUBY-1",
			Package:       "rexml",
			Version:       "3.2.3",
			FixedVersions: []string{"3.3.9"},
			ManifestRefs:  []dependencyv1.ManifestRef{{Manager: "gem", Path: "vagrant.gemspec"}},
		},
	}
	commands, stdlib := CommandsFromConsolidated(cons)
	// Version is preserved from FixedVersions, so "1.21.0" stays as-is
	if stdlib != "1.21.0" {
		t.Fatalf("expected stdlib recommendation 1.21.0, got %q", stdlib)
	}
	if len(commands) != 4 {
		for _, c := range commands {
			t.Logf("command: %s (manager=%s path=%s)", c.Command, c.Manager, c.Path)
		}
		t.Fatalf("expected 4 commands (go toolchain, go get, go mod tidy, gemspec edit); got %d", len(commands))
	}
	assertCommand(t, commands, "go get go@1.21.0", true)
	assertCommand(t, commands, "go get github.com/acme/lib@v1.1.0", true)
	assertCommand(t, commands, "go mod tidy", true)
	// Version preserved: 3.3.9 without v prefix
	assertCommand(t, commands, "Edit vagrant.gemspec to require rexml >= 3.3.9", false)
}

func TestCommandsFromConsolidatedMigration(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:    "GO-DIRECT",
			Package:      "github.com/example/widget",
			Version:      "v1.4.0",
			IsDirect:     true,
			ManifestRefs: []dependencyv1.ManifestRef{{Manager: "go", Path: "go.mod"}},
			Fix:          &vulnerability.FixVerdict{Status: vulnerability.FixStatusMigration, Version: "2.0.1", TargetModule: "github.com/example/widget/v2"},
		},
		{
			PrimaryID:    "GO-INDIRECT",
			Package:      "github.com/docker/docker",
			Version:      "v28.5.2+incompatible",
			PURL:         "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible",
			IsDirect:     false,
			ManifestRefs: []dependencyv1.ManifestRef{{Manager: "go", Path: "go.mod"}},
			Fix:          &vulnerability.FixVerdict{Status: vulnerability.FixStatusMigration, Version: "2.0.0-beta.14", TargetModule: "github.com/moby/moby/v2"},
		},
		{
			PrimaryID:    "GO-INDIRECT-CONTAINERD",
			Package:      "github.com/containerd/containerd",
			Version:      "v1.7.33",
			PURL:         "pkg:golang/github.com/containerd/containerd@1.7.33",
			IsDirect:     false,
			ManifestRefs: []dependencyv1.ManifestRef{{Manager: "go", Path: "go.mod"}},
			Fix:          &vulnerability.FixVerdict{Status: vulnerability.FixStatusMigration, Version: "2.1.9", TargetModule: "github.com/containerd/containerd/v2"},
		},
	}
	commands, _ := CommandsFromConsolidated(cons)

	// Direct migration: a concrete (but non-executable) go get on the target.
	assertCommand(t, commands, "go get github.com/example/widget/v2@v2.0.1", false)
	assertCommandTarget(t, commands, "go get github.com/example/widget/v2@v2.0.1", "v2.0.1")
	// Indirect migration: advise upgrading the importer, not a local go get.
	assertCommand(t, commands, "Upgrade the dependency that pulls this in (indirect; no in-place fix)", false)

	indirectMigrations := map[string]Command{}
	// An indirect migration must NOT emit a runnable go get for the target;
	// it would add an unused require that `go mod tidy` then drops.
	for _, c := range commands {
		if c.Command == "go get github.com/moby/moby/v2@v2.0.0-beta.14" {
			t.Errorf("indirect migration should not emit a go get for the target: %q", c.Command)
		}
		if c.Command == "go mod tidy" {
			t.Errorf("non-executable migrations should not trigger a go mod tidy follow-up")
		}
		if c.Command == "Upgrade the dependency that pulls this in (indirect; no in-place fix)" {
			indirectMigrations[c.Package] = c
		}
	}
	wantIndirect := map[string]struct {
		purl          string
		targetModule  string
		targetVersion string
	}{
		"github.com/docker/docker": {
			purl:          "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible",
			targetModule:  "github.com/moby/moby/v2",
			targetVersion: "v2.0.0-beta.14",
		},
		"github.com/containerd/containerd": {
			purl:          "pkg:golang/github.com/containerd/containerd@1.7.33",
			targetModule:  "github.com/containerd/containerd/v2",
			targetVersion: "v2.1.9",
		},
	}
	if len(indirectMigrations) != len(wantIndirect) {
		t.Fatalf("indirect migration command count = %d, want %d: %+v", len(indirectMigrations), len(wantIndirect), commands)
	}
	for pkgName, want := range wantIndirect {
		got, ok := indirectMigrations[pkgName]
		if !ok {
			t.Fatalf("missing indirect migration command for %s: %+v", pkgName, commands)
		}
		if got.PURL != want.purl {
			t.Errorf("%s purl = %q, want %q", pkgName, got.PURL, want.purl)
		}
		if got.TargetModule != want.targetModule {
			t.Errorf("%s target module = %q, want %q", pkgName, got.TargetModule, want.targetModule)
		}
		if got.TargetVersion != want.targetVersion {
			t.Errorf("%s target version = %q, want %q", pkgName, got.TargetVersion, want.targetVersion)
		}
		if !got.Migration {
			t.Errorf("%s command should be marked as migration", pkgName)
		}
		if got.Executable {
			t.Errorf("%s indirect migration command should not be executable", pkgName)
		}
	}
}

func TestGoModuleVersionNormalization(t *testing.T) {
	// Regression test: Go module versions from OSV may lack "v" prefix (e.g., "0.3.4")
	// but `go get` requires them (e.g., "v0.3.4")
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:     "GO-2024-1234",
			Package:       "github.com/google/osv-scalibr",
			Version:       "v0.3.0",
			FixedVersions: []string{"0.3.4"}, // Note: no "v" prefix, as OSV sometimes returns
			IsDirect:      true,
			ManifestRefs:  []dependencyv1.ManifestRef{{Manager: "go", Path: "./go.mod"}},
		},
	}
	commands, _ := CommandsFromConsolidated(cons)

	// Should normalize to v0.3.4
	assertCommand(t, commands, "go get github.com/google/osv-scalibr@v0.3.4", true)
	assertCommandTarget(t, commands, "go get github.com/google/osv-scalibr@v0.3.4", "v0.3.4")
}

func assertCommand(t *testing.T, commands []Command, want string, expectExecutable bool) {
	t.Helper()
	for _, c := range commands {
		if c.Command == want {
			if c.Executable != expectExecutable {
				t.Fatalf("command %q executable=%t, expected %t", want, c.Executable, expectExecutable)
			}
			return
		}
	}
	t.Fatalf("command %q not found in remediation plan", want)
}

func assertCommandTarget(t *testing.T, commands []Command, wantCommand, wantTarget string) {
	t.Helper()
	for _, c := range commands {
		if c.Command == wantCommand {
			if c.TargetVersion != wantTarget {
				t.Fatalf("command %q target version = %q, want %q", wantCommand, c.TargetVersion, wantTarget)
			}
			return
		}
	}
	t.Fatalf("command %q not found in remediation plan", wantCommand)
}

func TestDependencyGroupFlag(t *testing.T) {
	tests := []struct {
		manager string
		groups  []string
		want    string
	}{
		// npm flags
		{"npm", []string{"dev"}, "--save-dev"},
		{"npm", []string{"devDependencies"}, "--save-dev"},
		{"npm", []string{"optional"}, "--save-optional"},
		{"npm", []string{"optionalDependencies"}, "--save-optional"},
		{"npm", []string{"peer"}, "--save-peer"},
		{"npm", []string{"peerDependencies"}, "--save-peer"},
		{"npm", []string{"production"}, ""},
		{"npm", nil, ""},

		// pnpm flags (same as npm)
		{"pnpm", []string{"dev"}, "--save-dev"},
		{"pnpm", []string{"optional"}, "--save-optional"},

		// yarn flags
		{"yarn", []string{"dev"}, "--dev"},
		{"yarn", []string{"devDependencies"}, "--dev"},
		{"yarn", []string{"optional"}, "--optional"},
		{"yarn", []string{"peer"}, "--peer"},
		{"yarn", []string{"production"}, ""},

		// Unknown manager
		{"pip", []string{"dev"}, ""},
		{"go", []string{"dev"}, ""},

		// Case insensitivity
		{"NPM", []string{"DEV"}, "--save-dev"},
		{"Yarn", []string{"Optional"}, "--optional"},
	}

	for _, tt := range tests {
		t.Run(tt.manager+"_"+sliceToString(tt.groups), func(t *testing.T) {
			got := dependencyGroupFlag(tt.manager, tt.groups)
			if got != tt.want {
				t.Errorf("dependencyGroupFlag(%q, %v) = %q, want %q", tt.manager, tt.groups, got, tt.want)
			}
		})
	}
}

func sliceToString(s []string) string {
	if len(s) == 0 {
		return "empty"
	}
	return s[0]
}

func TestCommandsFromConsolidatedUV(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:     "PYSEC-1",
			Package:       "urllib3",
			Version:       "2.0.0",
			FixedVersions: []string{"2.6.3"},
			IsDirect:      true,
			ManifestRefs:  []dependencyv1.ManifestRef{{Manager: "uv", Path: "uv.lock"}},
		},
	}
	commands, _ := CommandsFromConsolidated(cons)
	if len(commands) == 0 {
		t.Fatalf("expected at least 1 command for UV remediation, got 0")
	}
	found := false
	for _, c := range commands {
		t.Logf("command: %s (manager=%s path=%s followUp=%s)", c.Command, c.Manager, c.Path, c.FollowUp)
		// Version should preserve original format (no "v" prefix for Python)
		if c.Manager == "uv" && c.Command == `uv add "urllib3>=2.6.3"` {
			found = true
			if c.FollowUp != "uv lock" {
				t.Errorf("expected uv follow-up 'uv lock', got %q", c.FollowUp)
			}
		}
	}
	if !found {
		t.Errorf("expected UV command 'uv add \"urllib3>=2.6.3\"' not found in: %v", commands)
	}
}

func TestCommandsFromConsolidatedMultiplePythonManagers(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:     "PYSEC-1",
			Package:       "requests",
			Version:       "2.25.0",
			FixedVersions: []string{"2.32.3"},
			IsDirect:      true,
			ManifestRefs: []dependencyv1.ManifestRef{
				{Manager: "pip", Path: "requirements.txt"},
				{Manager: "poetry", Path: "pyproject.toml"},
			},
		},
	}
	commands, _ := CommandsFromConsolidated(cons)
	if len(commands) < 2 {
		for _, c := range commands {
			t.Logf("command: %s (manager=%s)", c.Command, c.Manager)
		}
		t.Fatalf("expected at least 2 commands for pip and poetry, got %d", len(commands))
	}
	var foundPip, foundPoetry bool
	for _, c := range commands {
		if c.Manager == "pip" && c.Command == "pip install --upgrade requests==2.32.3" {
			foundPip = true
		}
		if c.Manager == "poetry" && c.Command == "poetry add requests@2.32.3" {
			foundPoetry = true
		}
	}
	if !foundPip {
		t.Error("pip command not found")
	}
	if !foundPoetry {
		t.Error("poetry command not found")
	}
}

func TestCommandsFromConsolidatedGoToolchain(t *testing.T) {
	// Test that both "stdlib" and "toolchain" package names trigger Go upgrade
	// OSV uses "stdlib" for standard library vulns and "toolchain" for go command vulns
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:     "GO-2025-1234",
			Package:       "toolchain", // Go command vulnerability
			Version:       "1.24.0",
			FixedVersions: []string{"1.24.9"},
		},
		{
			PrimaryID:     "GO-2025-5678",
			Package:       "stdlib", // Standard library vulnerability
			Version:       "1.24.0",
			FixedVersions: []string{"1.24.8"},
		},
	}
	commands, stdlib := CommandsFromConsolidated(cons)

	// Should pick the highest version needed (1.24.9 > 1.24.8)
	if stdlib != "1.24.9" {
		t.Errorf("expected stdlib recommendation 1.24.9, got %q", stdlib)
	}

	// Should generate exactly one Go toolchain upgrade command
	found := false
	for _, c := range commands {
		t.Logf("command: %s (manager=%s)", c.Command, c.Manager)
		if c.Command == "go get go@1.24.9" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'go get go@1.24.9' command for toolchain/stdlib upgrade")
	}
}

func TestCommandsFromConsolidatedMiseBackendTool(t *testing.T) {
	// A vulnerable mise-managed backend tool fixes via a deputy-internal config
	// edit, using the exact config key (with backend prefix), not the
	// canonical name.
	tests := []struct {
		name         string
		componentKey string
		wantCommand  string
	}{
		{"npm backend tool", "npm:lodash", "deputy:mise:update mise.toml npm:lodash 4.17.21 4.17.20"},
		{"cargo backend tool", "cargo:ripgrep", "deputy:mise:update mise.toml cargo:ripgrep 4.17.21 4.17.20"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cons := []vulnerability.Consolidated{
				{
					PrimaryID:     "GHSA-x",
					Package:       "lodash", // remapped canonical name
					Version:       "4.17.20",
					FixedVersions: []string{"4.17.21"},
					IsDirect:      true,
					ManifestRefs: []dependencyv1.ManifestRef{
						dependency.NewManifestRef("mise.toml", "mise", nil, tt.componentKey),
					},
				},
			}
			commands, _ := CommandsFromConsolidated(cons)
			if !slices.ContainsFunc(commands, func(c Command) bool { return c.Command == tt.wantCommand }) {
				t.Errorf("expected %q; commands=%+v", tt.wantCommand, commands)
			}
		})
	}
}

func TestCommandsFromConsolidatedStdlibSourceAware(t *testing.T) {
	// A Go stdlib CVE declared in BOTH go.mod and mise.toml must yield two
	// distinct fixes: bump the go directive AND bump the mise tool.
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:     "GO-2025-1234",
			Package:       "stdlib",
			Version:       "1.20.0",
			FixedVersions: []string{"1.20.1"},
			ManifestRefs: []dependencyv1.ManifestRef{
				{Path: "go.mod", Manager: "go"},
				dependency.NewManifestRef("mise.toml", "mise", nil, "go"),
			},
		},
	}
	commands, _ := CommandsFromConsolidated(cons)

	hasCommand := func(want string) bool {
		return slices.ContainsFunc(commands, func(c Command) bool { return c.Command == want })
	}
	if !hasCommand("go get go@1.20.1") {
		t.Errorf("expected go.mod toolchain command 'go get go@1.20.1'; commands=%+v", commands)
	}
	if !hasCommand("deputy:mise:update mise.toml go 1.20.1 1.20.0") {
		t.Errorf("expected mise command 'deputy:mise:update mise.toml go 1.20.1 1.20.0'; commands=%+v", commands)
	}
}

func TestCommandsFromConsolidatedStdlibMiseOnly(t *testing.T) {
	// A Go stdlib CVE declared ONLY in mise.toml must NOT emit a go.mod command.
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:     "GO-2025-1234",
			Package:       "stdlib",
			Version:       "1.20.0",
			FixedVersions: []string{"1.20.1"},
			ManifestRefs: []dependencyv1.ManifestRef{
				dependency.NewManifestRef("mise.toml", "mise", nil, "go"),
			},
		},
	}
	commands, _ := CommandsFromConsolidated(cons)

	hasCommand := func(want string) bool {
		return slices.ContainsFunc(commands, func(c Command) bool { return c.Command == want })
	}
	if hasCommand("go get go@1.20.1") {
		t.Errorf("did not expect a go.mod command for a mise-only stdlib finding; commands=%+v", commands)
	}
	if !hasCommand("deputy:mise:update mise.toml go 1.20.1 1.20.0") {
		t.Errorf("expected 'deputy:mise:update mise.toml go 1.20.1 1.20.0'; commands=%+v", commands)
	}
}

func TestCommandsFromConsolidatedStdlibMultipleCurrents(t *testing.T) {
	// Two stdlib findings with different current Go versions (e.g. a
	// multi-version array where both pins are vulnerable): the single mise
	// edit must carry every vulnerable version, sorted, so the apply replaces
	// each matching element.
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:     "GO-2025-1234",
			Package:       "stdlib",
			Version:       "1.20.0",
			FixedVersions: []string{"1.20.1"},
			ManifestRefs: []dependencyv1.ManifestRef{
				dependency.NewManifestRef("mise.toml", "mise", nil, "go"),
			},
		},
		{
			PrimaryID:     "GO-2025-5678",
			Package:       "stdlib",
			Version:       "1.21.0",
			FixedVersions: []string{"1.21.5"},
			ManifestRefs: []dependencyv1.ManifestRef{
				dependency.NewManifestRef("mise.toml", "mise", nil, "go"),
			},
		},
	}
	commands, _ := CommandsFromConsolidated(cons)

	want := "deputy:mise:update mise.toml go 1.21.5 1.20.0 1.21.0"
	if !slices.ContainsFunc(commands, func(c Command) bool { return c.Command == want }) {
		t.Errorf("expected %q; commands=%+v", want, commands)
	}
}

func TestCommandsFromConsolidatedGoToolchainOnly(t *testing.T) {
	// Test toolchain-only vulnerability (without stdlib)
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:     "GO-2025-0001",
			Package:       "toolchain",
			Version:       "1.23.0",
			FixedVersions: []string{"1.23.4"},
		},
	}
	commands, stdlib := CommandsFromConsolidated(cons)

	if stdlib != "1.23.4" {
		t.Errorf("expected stdlib recommendation 1.23.4 for toolchain vuln, got %q", stdlib)
	}

	found := false
	for _, c := range commands {
		if c.Command == "go get go@1.23.4" {
			found = true
		}
	}
	if !found {
		t.Error("expected go get command for toolchain vulnerability")
	}
}

func TestIsContainerfilePath(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		// Exact matches
		{"Dockerfile", true},
		{"dockerfile", true},
		{"DOCKERFILE", true},
		{"Containerfile", true},
		{"containerfile", true},
		{"CONTAINERFILE", true},

		// Extension patterns
		{"app.dockerfile", true},
		{"app.Dockerfile", true},
		{"prod.containerfile", true},
		{"prod.Containerfile", true},

		// Prefix patterns (e.g., Dockerfile.prod)
		{"Dockerfile.prod", true},
		{"dockerfile.dev", true},
		{"Containerfile.prod", true},
		{"containerfile.dev", true},

		// Not container files
		{"docker-compose.yml", false},
		{"docker-compose.yaml", false},
		{"requirements.txt", false},
		{"package.json", false},
		{"go.mod", false},
		{"dockerfiler", false},
		{"my-dockerfile-backup", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isContainerfilePath(tt.name); got != tt.want {
				t.Errorf("isContainerfilePath(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// TestCommandsFromConsolidatedSkipsInstallArtifactManifests is the regression
// for temporalio/deputy#40: a vulnerable package whose manifest is vendored
// inside an install-artifact tree (e.g. a Cargo.toml under .venv/site-packages)
// must not produce a remediation command, since editing the installed copy
// fixes nothing. The source-of-truth manifest at the repo root still does.
func TestCommandsFromConsolidatedSkipsInstallArtifactManifests(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:     "GHSA-test",
			Package:       "somecrate",
			Version:       "1.0.0",
			Ecosystem:     "crates.io",
			IsDirect:      true,
			FixedVersions: []string{"1.0.1"},
			ManifestRefs: []dependencyv1.ManifestRef{
				{Manager: "cargo", Path: "Cargo.toml"},
				{Manager: "cargo", Path: ".venv/lib/python3.12/site-packages/wheelpkg/Cargo.toml"},
			},
		},
	}

	commands, _ := CommandsFromConsolidated(cons)

	var sawRoot bool
	for _, c := range commands {
		if inventory.IsDependencyInstallPath(c.Path) {
			t.Errorf("emitted remediation targeting install-artifact manifest %q (command %q)", c.Path, c.Command)
		}
		if c.Path == "Cargo.toml" {
			sawRoot = true
		}
	}
	if !sawRoot {
		t.Error("expected a remediation command for the source-of-truth Cargo.toml")
	}
}

func TestApplyGuidanceAdaptsIndirectMigrationHints(t *testing.T) {
	commands := []Command{
		{
			Package:       "github.com/docker/docker",
			Version:       "v28.5.2+incompatible",
			PURL:          "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible",
			TargetVersion: "2.0.0-beta.14",
			TargetModule:  "github.com/moby/moby/v2",
			Migration:     true,
			IsDirect:      false,
			Executable:    false,
			Hint:          "use dependency graph context to find the direct dependency that pulls this in",
		},
	}

	mcpCommands := ApplyGuidance(commands, MCPGuidance())
	if got := mcpCommands[0].Hint; !strings.Contains(got, `graph_why`) || !strings.Contains(got, commands[0].PURL) || !strings.Contains(got, "resolveTransitives true") {
		t.Fatalf("MCP hint = %q, want graph_why, PURL, and resolveTransitives", got)
	}
	if strings.Contains(mcpCommands[0].Hint, "--with-graph") {
		t.Fatalf("MCP hint leaked CLI flag: %q", mcpCommands[0].Hint)
	}

	cliCommands := ApplyGuidance(commands, CLIGuidance())
	if got := cliCommands[0].Hint; !strings.Contains(got, "--resolve-transitives") || !strings.Contains(got, `deputy graph why`) {
		t.Fatalf("CLI hint = %q, want CLI graph guidance with transitive resolution", got)
	}

	apiCommands := ApplyGuidance(commands, APIGuidance())
	if got := apiCommands[0].Hint; !strings.Contains(got, "GraphService.WhyDependency") || !strings.Contains(got, "use_proxy") || !strings.Contains(got, "use_git") {
		t.Fatalf("API hint = %q, want GraphService guidance with transitive resolution", got)
	}

	if commands[0].Hint == mcpCommands[0].Hint {
		t.Fatal("ApplyGuidance mutated or failed to adapt the original command")
	}
}

// TestStdlibCommandsSkipsVendoredGoMod covers the toolchain-fallback edge of
// temporalio/deputy#40: a Go stdlib finding whose only source is a go.mod
// vendored inside an installed tree must not produce a `go get go@X` command,
// since the fallback would otherwise emit one against a synthetic go.mod path.
func TestStdlibCommandsSkipsVendoredGoMod(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:     "GO-2026-0001",
			Package:       "stdlib",
			Version:       "1.25.0",
			Ecosystem:     "Go",
			FixedVersions: []string{"1.25.11"},
			ManifestRefs: []dependencyv1.ManifestRef{
				{Manager: "go", Path: ".venv/lib/python3.10/site-packages/wheelpkg/sdk-core/go.mod"},
			},
		},
	}

	commands, _ := CommandsFromConsolidated(cons)

	if len(commands) != 0 {
		t.Errorf("expected no commands for a stdlib finding sourced only from a vendored go.mod, got %d: %+v", len(commands), commands)
	}
}
