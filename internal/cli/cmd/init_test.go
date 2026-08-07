package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/policy"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantFiles  []string
		wantOutput string
	}{
		{
			name:       "default init",
			args:       []string{"init"},
			wantFiles:  []string{".deputy.yaml", "policy/deputy.yaml"},
			wantOutput: "Created:",
		},
		{
			name:       "config only",
			args:       []string{"init", "--config-only"},
			wantFiles:  []string{".deputy.yaml"},
			wantOutput: ".deputy.yaml",
		},
		{
			name:       "policy only",
			args:       []string{"init", "--policy-only"},
			wantFiles:  []string{"policy/deputy.yaml"},
			wantOutput: "policy/deputy.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			root := &cobra.Command{Use: "deputy"}
			AddInitCommand(root)

			var stdout bytes.Buffer
			root.SetOut(&stdout)
			root.SetArgs(append(tt.args, tmpDir))

			if err := root.Execute(); err != nil {
				t.Errorf("Execute() error = %v", err)
			}

			// Check expected files exist
			for _, file := range tt.wantFiles {
				path := filepath.Join(tmpDir, file)
				if _, err := os.Stat(path); os.IsNotExist(err) {
					t.Errorf("Expected file %s to exist", file)
				}
			}

			// Check output
			if tt.wantOutput != "" && !strings.Contains(stdout.String(), tt.wantOutput) {
				t.Errorf("Output %q does not contain %q", stdout.String(), tt.wantOutput)
			}
		})
	}
}

func TestInit_ExistingFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create existing config file
	configPath := filepath.Join(tmpDir, ".deputy.yaml")
	if err := os.WriteFile(configPath, []byte("existing: true"), 0644); err != nil {
		t.Fatal(err)
	}

	root := &cobra.Command{Use: "deputy"}
	AddInitCommand(root)

	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetArgs([]string{"init", tmpDir})

	if err := root.Execute(); err != nil {
		t.Errorf("Execute() error = %v", err)
	}

	// Check existing file was not overwritten
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "existing: true") {
		t.Error("Existing file was overwritten without --force")
	}

	// Check output mentions skipped file
	if !strings.Contains(stdout.String(), "Skipped") {
		t.Error("Expected output to mention skipped file")
	}
}

func TestInit_Force(t *testing.T) {
	tmpDir := t.TempDir()

	// Create existing config file
	configPath := filepath.Join(tmpDir, ".deputy.yaml")
	if err := os.WriteFile(configPath, []byte("existing: true"), 0644); err != nil {
		t.Fatal(err)
	}

	root := &cobra.Command{Use: "deputy"}
	AddInitCommand(root)

	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetArgs([]string{"init", "--force", tmpDir})

	if err := root.Execute(); err != nil {
		t.Errorf("Execute() error = %v", err)
	}

	// Check existing file was overwritten
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "existing: true") {
		t.Error("Existing file was not overwritten with --force")
	}
}

func TestInit_ConfigContent(t *testing.T) {
	tmpDir := t.TempDir()

	root := &cobra.Command{Use: "deputy"}
	AddInitCommand(root)

	root.SetArgs([]string{"init", tmpDir})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	// Check config file content
	configContent, err := os.ReadFile(filepath.Join(tmpDir, ".deputy.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	expectedStrings := []string{
		"Deputy Configuration",
		"logging:",
		"level:",
	}

	for _, s := range expectedStrings {
		if !strings.Contains(string(configContent), s) {
			t.Errorf("Config file missing expected content: %s", s)
		}
	}
}

func TestInit_PolicyContent(t *testing.T) {
	tmpDir := t.TempDir()

	root := &cobra.Command{Use: "deputy"}
	AddInitCommand(root)

	root.SetArgs([]string{"init", tmpDir})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}

	// Check policy file content
	policyContent, err := os.ReadFile(filepath.Join(tmpDir, "policy", "deputy.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	expectedStrings := []string{
		"policies:",
		"block-critical-high",
		"vulnerability.?advisory.severity.level",
		"action: deny",
	}

	for _, s := range expectedStrings {
		if !strings.Contains(string(policyContent), s) {
			t.Errorf("Policy file missing expected content: %s", s)
		}
	}
}

// TestInit_PolicyTemplateEvaluates is the drift gate for the starter policy:
// the file that `deputy init` generates must compile AND evaluate cleanly
// against representative Finding payloads at its declared entrypoint, and the
// rules must actually fire on the findings they claim to catch. If the
// template ever references fields that do not exist on the runtime contract
// (e.g. vulnerability.severity or vulnerability.inKEV), evaluation errors and
// this test fails.
func TestInit_PolicyTemplateEvaluates(t *testing.T) {
	tmpDir := t.TempDir()

	root := &cobra.Command{Use: "deputy"}
	AddInitCommand(root)
	root.SetArgs([]string{"init", "--policy-only", tmpDir})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(tmpDir, "policy", "deputy.yaml")

	inKEV := true
	epss := 0.9
	tests := []struct {
		name          string
		vulnerability *vulnerabilityv1.Finding
		// wantDenyFrom names the policy expected to deny the finding
		// (evaluatePoliciesForCommand turns the first deny into an error).
		// Empty means the finding must pass without a deny.
		wantDenyFrom string
		// wantWarn expects exactly one warn action when no deny fires.
		wantWarn bool
	}{
		{
			name: "critical finding in KEV with high EPSS",
			vulnerability: &vulnerabilityv1.Finding{
				AdvisoryId: "CVE-2021-23337",
				Package:    &dependencyv1.Package{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", Direct: true},
				Advisory: &vulnerabilityv1.Advisory{
					Id:            "CVE-2021-23337",
					FixedVersions: []string{"4.17.21"},
					Severity:      &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL},
				},
				InKev:    &inKEV,
				Epss:     &epss,
				Affected: true,
			},
			wantDenyFrom: "block-critical-high",
		},
		{
			name: "high severity finding",
			vulnerability: &vulnerabilityv1.Finding{
				AdvisoryId: "CVE-2024-0001",
				Package:    &dependencyv1.Package{Name: "foo", Version: "1.0.0", Ecosystem: "npm", Direct: true},
				Advisory: &vulnerabilityv1.Advisory{
					Id:       "CVE-2024-0001",
					Severity: &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH},
				},
				Affected: true,
			},
			wantDenyFrom: "block-critical-high",
		},
		{
			name: "medium severity finding without enrichment",
			vulnerability: &vulnerabilityv1.Finding{
				AdvisoryId: "CVE-2024-0002",
				Package:    &dependencyv1.Package{Name: "bar", Version: "1.0.0", Ecosystem: "npm", Direct: true},
				Advisory: &vulnerabilityv1.Advisory{
					Id:       "CVE-2024-0002",
					Severity: &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM},
				},
				Affected: true,
			},
			wantWarn: true,
		},
		{
			name: "low severity finding",
			vulnerability: &vulnerabilityv1.Finding{
				AdvisoryId: "CVE-2024-0003",
				Package:    &dependencyv1.Package{Name: "baz", Version: "2.0.0", Ecosystem: "go", Direct: false},
				Advisory: &vulnerabilityv1.Advisory{
					Id:       "CVE-2024-0003",
					Severity: &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW},
				},
				Affected: true,
			},
		},
		{
			name: "finding without advisory details",
			vulnerability: &vulnerabilityv1.Finding{
				AdvisoryId: "CVE-2024-0004",
				Package:    &dependencyv1.Package{Name: "qux", Version: "3.0.0", Ecosystem: "pypi", Direct: true},
				Affected:   true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := map[string]any{"vulnerability": tt.vulnerability}
			actions, err := evaluatePoliciesForCommand(t.Context(), []string{policyPath}, payload, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{})
			if err != nil {
				// Distinguish an expected policy denial from a template that
				// references fields missing on the runtime contract.
				if !strings.Contains(err.Error(), "denied command") {
					t.Fatalf("generated starter policy failed to evaluate: %v", err)
				}
				if tt.wantDenyFrom == "" {
					t.Fatalf("unexpected deny from starter policy: %v", err)
				}
				if !strings.Contains(err.Error(), tt.wantDenyFrom) {
					t.Errorf("deny error %q does not mention policy %q", err, tt.wantDenyFrom)
				}
				return
			}
			if tt.wantDenyFrom != "" {
				t.Fatalf("expected deny from %q, got actions %+v", tt.wantDenyFrom, actions)
			}
			var warns int
			for _, a := range actions {
				if a.Type == "warn" {
					warns++
				}
			}
			if tt.wantWarn && warns != 1 {
				t.Errorf("expected exactly one warn action, got %d (%+v)", warns, actions)
			}
			if !tt.wantWarn && warns != 0 {
				t.Errorf("expected no warn actions, got %d (%+v)", warns, actions)
			}
		})
	}
}

func TestDetectEcosystems(t *testing.T) {
	tests := []struct {
		name     string
		files    []string
		expected []string
	}{
		{
			name:     "go project",
			files:    []string{"go.mod", "go.sum", "main.go"},
			expected: []string{"Go"},
		},
		{
			name:     "npm project",
			files:    []string{"package.json", "package-lock.json"},
			expected: []string{"npm"},
		},
		{
			name:     "python project",
			files:    []string{"requirements.txt", "setup.py"},
			expected: []string{"Python"},
		},
		{
			name:     "multi-ecosystem",
			files:    []string{"go.mod", "package.json", "Dockerfile"},
			expected: []string{"Docker", "Go", "npm"},
		},
		{
			name:     "rust project",
			files:    []string{"Cargo.toml", "Cargo.lock"},
			expected: []string{"Rust"},
		},
		{
			name:     "empty directory",
			files:    []string{},
			expected: nil,
		},
		{
			name:     "no manifests",
			files:    []string{"main.go", "README.md"},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Create the files
			for _, file := range tt.files {
				path := filepath.Join(tmpDir, file)
				if err := os.WriteFile(path, []byte(""), 0644); err != nil {
					t.Fatal(err)
				}
			}

			got := detectEcosystems(tmpDir)

			if len(got) != len(tt.expected) {
				t.Errorf("detectEcosystems() got %v, want %v", got, tt.expected)
				return
			}

			for i, eco := range got {
				if eco != tt.expected[i] {
					t.Errorf("detectEcosystems()[%d] = %q, want %q", i, eco, tt.expected[i])
				}
			}
		})
	}
}

func TestEcosystemTip(t *testing.T) {
	tests := []struct {
		eco      string
		wantTip  bool
		contains string
	}{
		{"Go", true, "graph why"},
		{"npm", true, "proxy npm"},
		{"Python", true, "proxy pypi"},
		{"Ruby", true, "proxy rubygems"},
		{"Unknown", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.eco, func(t *testing.T) {
			tip := ecosystemTip(tt.eco)
			if tt.wantTip && tip == "" {
				t.Errorf("ecosystemTip(%q) returned empty, wanted tip", tt.eco)
			}
			if !tt.wantTip && tip != "" {
				t.Errorf("ecosystemTip(%q) = %q, wanted empty", tt.eco, tip)
			}
			if tt.contains != "" && !strings.Contains(tip, tt.contains) {
				t.Errorf("ecosystemTip(%q) = %q, wanted to contain %q", tt.eco, tip, tt.contains)
			}
		})
	}
}
