package remediation

import (
	"testing"

	analysis "github.com/picatz/deputy/internal/analysis"
)

func TestCommandsFromVulnerabilitiesGeneratesPlan(t *testing.T) {
	vulns := []analysis.Vulnerability{
		{
			ID:            "STD-1",
			Package:       "stdlib",
			Version:       "1.20.0",
			FixedVersions: []string{"1.21.0"},
			Affected:      true,
		},
		{
			ID:            "GO-1",
			Package:       "github.com/acme/lib",
			Version:       "v1.0.0",
			FixedVersions: []string{"v1.1.0"},
			IsDirect:      true,
			Affected:      true,
			ManifestRefs: []analysis.ManifestReference{
				{Manager: "go", Path: "./go.mod"},
			},
		},
		{
			ID:            "RUBY-1",
			Package:       "rexml",
			Version:       "3.2.3",
			FixedVersions: []string{"3.3.9"},
			Affected:      true,
			ManifestRefs: []analysis.ManifestReference{
				{Manager: "gem", Path: "vagrant.gemspec"},
			},
		},
	}
	commands, stdlib := CommandsFromVulnerabilities(vulns)
	if stdlib != "v1.21.0" {
		t.Fatalf("expected stdlib recommendation v1.21.0, got %q", stdlib)
	}
	if len(commands) != 3 {
		for _, c := range commands {
			t.Logf("command: %s (manager=%s path=%s)", c.Command, c.Manager, c.Path)
		}
		t.Fatalf("expected 3 commands (go get, go mod tidy, gemspec edit); got %d", len(commands))
	}
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
