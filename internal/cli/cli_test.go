package cli

import (
	"log/slog"
	"os"
	"slices"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/spf13/cobra"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    slog.Level
		wantErr bool
	}{
		{name: "debug", input: "debug", want: slog.LevelDebug, wantErr: false},
		{name: "info", input: "info", want: slog.LevelInfo, wantErr: false},
		{name: "warn", input: "warn", want: slog.LevelWarn, wantErr: false},
		{name: "error", input: "error", want: slog.LevelError, wantErr: false},
		{name: "empty defaults to info", input: "", want: slog.LevelInfo, wantErr: false},
		{name: "case insensitive", input: "DEBUG", want: slog.LevelDebug, wantErr: false},
		{name: "unknown", input: "unknown", want: slog.LevelInfo, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseLogLevel(test.input)
			if (err != nil) != test.wantErr {
				t.Errorf("parseLogLevel() error = %v, wantErr %v", err, test.wantErr)
				return
			}
			if !test.wantErr && got != test.want {
				t.Errorf("parseLogLevel() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestNewRoot(t *testing.T) {
	cmd := newRoot()
	if cmd.Use != "deputy" {
		t.Errorf("expected Use to be 'deputy', got %q", cmd.Use)
	}
	if !cmd.HasAvailableSubCommands() {
		t.Error("expected subcommands to be registered")
	}

	// Check for specific subcommands
	expectedCmds := []string{"scan", "fix", "triage", "policy", "proxy", "diff", "list", "sbom"}
	for _, name := range expectedCmds {
		if !slices.ContainsFunc(cmd.Commands(), func(c *cobra.Command) bool {
			return c.Name() == name
		}) {
			t.Errorf("expected subcommand %q not found", name)
		}
	}
}

func TestDefaultLogLevel(t *testing.T) {
	// Save original env
	orig := os.Getenv("DEPUTY_LOG_LEVEL")
	defer os.Setenv("DEPUTY_LOG_LEVEL", orig)

	tests := []struct {
		name string
		env  string
		want string
	}{
		{name: "default", env: "", want: "warn"},
		{name: "set", env: "debug", want: "debug"},
		{name: "whitespace", env: "  info  ", want: "info"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.env == "" {
				os.Unsetenv("DEPUTY_LOG_LEVEL")
			} else {
				os.Setenv("DEPUTY_LOG_LEVEL", test.env)
			}
			if got := defaultLogLevel(); got != test.want {
				t.Errorf("defaultLogLevel() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestDefaultLogFormat(t *testing.T) {
	// Save original env
	orig := os.Getenv("DEPUTY_LOG_FORMAT")
	defer os.Setenv("DEPUTY_LOG_FORMAT", orig)

	tests := []struct {
		name string
		env  string
		want string
	}{
		{name: "default", env: "", want: "text"},
		{name: "set", env: "json", want: "json"},
		{name: "whitespace", env: "  json  ", want: "json"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.env == "" {
				os.Unsetenv("DEPUTY_LOG_FORMAT")
			} else {
				os.Setenv("DEPUTY_LOG_FORMAT", test.env)
			}
			if got := defaultLogFormat(); got != test.want {
				t.Errorf("defaultLogFormat() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestIsInGitRepo(t *testing.T) {
	// Save current wd
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(wd)

	// Case 1: Not a git repo
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	if isInGitRepo() {
		t.Error("expected isInGitRepo() to be false in empty temp dir")
	}

	// Case 2: Git repo
	_, err = git.PlainInit(tmp, false)
	if err != nil {
		t.Fatalf("failed to init git repo: %v", err)
	}
	if !isInGitRepo() {
		t.Error("expected isInGitRepo() to be true in git repo")
	}
}
