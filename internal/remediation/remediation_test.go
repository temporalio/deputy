package remediation

import (
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
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
