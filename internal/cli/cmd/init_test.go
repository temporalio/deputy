package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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
		"vulnerability.severity",
		"action: deny",
	}

	for _, s := range expectedStrings {
		if !strings.Contains(string(policyContent), s) {
			t.Errorf("Policy file missing expected content: %s", s)
		}
	}
}
