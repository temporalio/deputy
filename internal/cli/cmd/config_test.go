package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name       string
		configYAML string
		wantErr    bool
		wantOutput string
	}{
		{
			name: "valid config",
			configYAML: `
logging:
  level: info
  format: text
`,
			wantErr:    false,
			wantOutput: "Configuration valid",
		},
		{
			name: "invalid log level",
			configYAML: `
logging:
  level: invalid
`,
			wantErr: true,
		},
		{
			name: "invalid log format",
			configYAML: `
logging:
  format: invalid
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp config file
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, ".deputy.yaml")
			if err := os.WriteFile(configPath, []byte(tt.configYAML), 0644); err != nil {
				t.Fatal(err)
			}

			// Set up command
			root := &cobra.Command{Use: "deputy"}
			AddConfigCommand(root)

			var stdout, stderr bytes.Buffer
			root.SetOut(&stdout)
			root.SetErr(&stderr)
			root.SetArgs([]string{"config", "validate", configPath})

			err := root.Execute()
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && tt.wantOutput != "" {
				if !strings.Contains(stdout.String(), tt.wantOutput) {
					t.Errorf("Output %q does not contain %q", stdout.String(), tt.wantOutput)
				}
			}
		})
	}
}

func TestConfigValidate_NoFile(t *testing.T) {
	root := &cobra.Command{Use: "deputy"}
	AddConfigCommand(root)

	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetArgs([]string{"config", "validate", "/nonexistent/file.yaml"})

	err := root.Execute()
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestConfigShow(t *testing.T) {
	tests := []struct {
		name       string
		format     string
		wantOutput string
	}{
		{
			name:       "yaml format",
			format:     "yaml",
			wantOutput: "logging:",
		},
		{
			name:       "json format",
			format:     "json",
			wantOutput: `"logging"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := &cobra.Command{Use: "deputy"}
			AddConfigCommand(root)

			var stdout bytes.Buffer
			root.SetOut(&stdout)
			root.SetArgs([]string{"config", "show", "--format", tt.format})

			if err := root.Execute(); err != nil {
				t.Errorf("Execute() error = %v", err)
			}

			if !strings.Contains(stdout.String(), tt.wantOutput) {
				t.Errorf("Output %q does not contain %q", stdout.String(), tt.wantOutput)
			}
		})
	}
}

func TestConfigPath(t *testing.T) {
	root := &cobra.Command{Use: "deputy"}
	AddConfigCommand(root)

	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetArgs([]string{"config", "path"})

	if err := root.Execute(); err != nil {
		t.Errorf("Execute() error = %v", err)
	}

	// Should either show a path or "No configuration file found"
	output := stdout.String()
	if !strings.Contains(output, ".deputy") && !strings.Contains(output, "No configuration file found") {
		t.Errorf("Unexpected output: %q", output)
	}
}
