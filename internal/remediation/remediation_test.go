package remediation

import (
	"testing"

	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/vulnerability"
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
			ManifestRefs:  []dependency.ManifestRef{{Manager: "go", Path: "./go.mod"}},
		},
		{
			PrimaryID:     "RUBY-1",
			Package:       "rexml",
			Version:       "3.2.3",
			FixedVersions: []string{"3.3.9"},
			ManifestRefs:  []dependency.ManifestRef{{Manager: "gem", Path: "vagrant.gemspec"}},
		},
	}
	commands, stdlib := CommandsFromConsolidated(cons)
	if stdlib != "v1.21.0" {
		t.Fatalf("expected stdlib recommendation v1.21.0, got %q", stdlib)
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
	assertCommand(t, commands, "Edit vagrant.gemspec to require rexml >= v3.3.9", false)
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
