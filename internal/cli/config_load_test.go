package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/temporalio/deputy/internal/config"
	deputyerrors "github.com/temporalio/deputy/internal/errors"
)

// isolatedConfigDir puts the test in an empty working directory that also acts
// as the home directory, so config discovery cannot pick up the developer's own
// .deputy.yaml (FindConfigFile searches the working directory and then $HOME).
// DEPUTY_CONFIG and DEPUTY_LOG_LEVEL are cleared for the same reason: an
// inherited value would decide the outcome instead of the fixture.
func isolatedConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("DEPUTY_CONFIG", "")
	t.Setenv("DEPUTY_LOG_LEVEL", "")
	t.Chdir(dir)
	return dir
}

// writeConfigFile writes a .deputy.yaml into the isolated working directory.
func writeConfigFile(t *testing.T, contents string) {
	t.Helper()
	if err := os.WriteFile(".deputy.yaml", []byte(contents), 0o644); err != nil {
		t.Fatalf("write .deputy.yaml: %v", err)
	}
}

// TestLoadRuntimeConfig pins the distinction the CLI depends on: no config file
// is normal and yields usable defaults, while a config file that exists but
// cannot be parsed or validated is an error the caller must treat as fatal. The
// silent-nil behavior this replaces let a broken file disable egress
// allowlists, advisory sources, and OTel with no diagnostic at all.
func TestLoadRuntimeConfig(t *testing.T) {
	tests := []struct {
		name string
		// writeFile is false for the absent-config case.
		writeFile bool
		contents  string
		// env is applied after the isolating setup, for the case where the
		// environment rather than a file carries the bad value.
		env               map[string]string
		wantErr           bool
		wantErrHas        []string
		wantSuggestionHas string
		checkConfig       func(t *testing.T, cfg *config.Config)
	}{
		{
			name:      "no config file loads defaults without error",
			writeFile: false,
			checkConfig: func(t *testing.T, cfg *config.Config) {
				if cfg == nil {
					t.Fatal("cfg is nil; an absent config file must still yield defaults")
				}
				if cfg.Logging.Level == "" {
					t.Error("expected default logging level to be populated")
				}
			},
		},
		{
			name:      "unparseable yaml is an error",
			writeFile: true,
			contents:  "logging:\n  level: \"unclosed\n   bogus: [1, 2\n",
			wantErr:   true,
			// The path must be named: the offending file can live in the
			// home directory, far from where the command was run.
			wantErrHas:        []string{"failed to load config from", ".deputy.yaml", "failed to parse config file"},
			wantSuggestionHas: "deputy config validate",
		},
		{
			name:              "valid yaml with an invalid value is an error",
			writeFile:         true,
			contents:          "logging:\n  level: shouty\n",
			wantErr:           true,
			wantErrHas:        []string{"failed to load config from", ".deputy.yaml", "validation failed for logging.level"},
			wantSuggestionHas: "deputy config validate",
		},
		{
			// With no file to blame, the error must not point at
			// 'config validate', which only reads files.
			name:              "invalid environment value is an error without a file",
			writeFile:         false,
			env:               map[string]string{"DEPUTY_LOG_LEVEL": "shouty"},
			wantErr:           true,
			wantErrHas:        []string{"failed to load config", "validation failed for logging.level"},
			wantSuggestionHas: "DEPUTY_* environment variables",
		},
		{
			name:      "valid config is loaded and honored",
			writeFile: true,
			contents: "logging:\n  level: debug\negress:\n  allow_loopback: true\n" +
				"advisory_sources:\n  - url: \"https://advisories.example.com\"\n",
			checkConfig: func(t *testing.T, cfg *config.Config) {
				if cfg == nil {
					t.Fatal("cfg is nil for a valid config file")
				}
				if cfg.Logging.Level != "debug" {
					t.Errorf("Logging.Level = %q, want %q", cfg.Logging.Level, "debug")
				}
				if cfg.Egress == nil || !cfg.Egress.AllowLoopback {
					t.Errorf("Egress.AllowLoopback not honored: %+v", cfg.Egress)
				}
				if len(cfg.AdvisorySources) != 1 || cfg.AdvisorySources[0].URL != "https://advisories.example.com" {
					t.Errorf("AdvisorySources = %+v, want the single configured URL", cfg.AdvisorySources)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isolatedConfigDir(t)
			if test.writeFile {
				writeConfigFile(t, test.contents)
			}
			for k, v := range test.env {
				t.Setenv(k, v)
			}

			cfg, err := loadRuntimeConfig()

			if test.wantErr {
				if err == nil {
					t.Fatalf("loadRuntimeConfig() error = nil, want an error; cfg = %+v", cfg)
				}
				if cfg != nil {
					t.Errorf("loadRuntimeConfig() returned a config alongside an error: %+v", cfg)
				}
				for _, want := range test.wantErrHas {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q does not contain %q", err.Error(), want)
					}
				}
				if got := deputyerrors.GetSuggestion(err); !strings.Contains(got, test.wantSuggestionHas) {
					t.Errorf("suggestion = %q, want it to contain %q", got, test.wantSuggestionHas)
				}
				return
			}

			if err != nil {
				t.Fatalf("loadRuntimeConfig() error = %v, want nil", err)
			}
			if test.checkConfig != nil {
				test.checkConfig(t, cfg)
			}
		})
	}
}

// TestRootRefusesUnloadableConfig proves the load failure reaches command
// execution rather than stopping at loadRuntimeConfig: a command must fail
// instead of running on defaults. It drives the root command the way Run does,
// with the error loadRuntimeConfig produced for a real broken file.
func TestRootRefusesUnloadableConfig(t *testing.T) {
	tests := []struct {
		name     string
		contents string
	}{
		{name: "unparseable yaml", contents: "logging:\n  level: \"unclosed\n   bogus: [1, 2\n"},
		{name: "invalid value", contents: "logging:\n  level: shouty\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isolatedConfigDir(t)
			writeConfigFile(t, test.contents)

			cfg, cfgErr := loadRuntimeConfig()
			if cfgErr == nil {
				t.Fatalf("loadRuntimeConfig() error = nil for %q; the rest of this test is meaningless", test.contents)
			}
			if cfg != nil {
				t.Errorf("cfg = %+v, want nil", cfg)
			}

			// "version" is the cheapest real command: it touches no network
			// and no filesystem, so the only thing that can fail it is the
			// config gate.
			err := executeRootWithConfigErr(t, cfgErr, "version")
			if err == nil {
				t.Fatal("command succeeded with an unloadable config; it ran on defaults instead of failing")
			}
			if !errors.Is(err, cfgErr) {
				t.Errorf("command error = %v, want the config load error %v", err, cfgErr)
			}
		})
	}
}

// TestRootAllowsConfigCommandsWithUnloadableConfig pins the one exemption: the
// commands that diagnose a broken config file must stay runnable when the file
// is broken, otherwise the failure message has no follow-up.
func TestRootAllowsConfigCommandsWithUnloadableConfig(t *testing.T) {
	isolatedConfigDir(t)
	writeConfigFile(t, "logging:\n  level: shouty\n")

	_, cfgErr := loadRuntimeConfig()
	if cfgErr == nil {
		t.Fatal("loadRuntimeConfig() error = nil; fixture is not broken")
	}

	if err := executeRootWithConfigErr(t, cfgErr, "config", "path"); err != nil {
		t.Errorf("'config path' failed with an unloadable config: %v", err)
	}
}

// TestRootRunsWithValidConfig guards the other direction, so the gate cannot
// pass by failing everything: a loadable config file leaves commands runnable.
func TestRootRunsWithValidConfig(t *testing.T) {
	isolatedConfigDir(t)
	writeConfigFile(t, "logging:\n  level: debug\n")

	cfg, cfgErr := loadRuntimeConfig()
	if cfgErr != nil {
		t.Fatalf("loadRuntimeConfig() error = %v, want nil", cfgErr)
	}
	if cfg == nil {
		t.Fatal("cfg is nil for a valid config file")
	}

	if err := executeRootWithConfigErr(t, nil, "version"); err != nil {
		t.Errorf("'version' failed with a valid config: %v", err)
	}
}

// TestRootRunsWithoutConfigFile pins the silent-success case: with no config
// file anywhere, commands run and nothing is written to the command's error
// stream.
func TestRootRunsWithoutConfigFile(t *testing.T) {
	isolatedConfigDir(t)

	cfg, cfgErr := loadRuntimeConfig()
	if cfgErr != nil {
		t.Fatalf("loadRuntimeConfig() error = %v, want nil for an absent config file", cfgErr)
	}
	if cfg == nil {
		t.Fatal("cfg is nil for an absent config file")
	}

	var stderr bytes.Buffer
	root := newRoot(nil)
	root.SetArgs([]string{"version"})
	root.SetOut(io.Discard)
	root.SetErr(&stderr)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Errorf("'version' failed with no config file: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty: an absent config file must stay silent", stderr.String())
	}
}

// TestInConfigCommandTree covers the exemption predicate directly, including
// the case that must not be exempt: the root command itself is named "deputy",
// and a top-level command must never inherit the config exemption.
func TestInConfigCommandTree(t *testing.T) {
	root := newRoot(nil)

	find := func(t *testing.T, args ...string) *cobra.Command {
		t.Helper()
		cmd, _, err := root.Find(args)
		if err != nil {
			t.Fatalf("Find(%v): %v", args, err)
		}
		return cmd
	}

	tests := []struct {
		name string
		args []string
		want bool
	}{
		{name: "config parent", args: []string{"config"}, want: true},
		{name: "config show", args: []string{"config", "show"}, want: true},
		{name: "config validate", args: []string{"config", "validate"}, want: true},
		{name: "root", args: nil, want: false},
		{name: "version", args: []string{"version"}, want: false},
		{name: "scan", args: []string{"scan"}, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := inConfigCommandTree(find(t, test.args...)); got != test.want {
				t.Errorf("inConfigCommandTree(%v) = %v, want %v", test.args, got, test.want)
			}
		})
	}

	// The exemption keys on the top-level config command, not on the name
	// alone, so a command named "config" nested under something else must not
	// pick it up and become runnable on a config file that failed to load.
	t.Run("nested command named config is not exempt", func(t *testing.T) {
		fake := &cobra.Command{Use: "deputy"}
		proxy := &cobra.Command{Use: "proxy"}
		nested := &cobra.Command{Use: "config"}
		proxy.AddCommand(nested)
		fake.AddCommand(proxy)

		if inConfigCommandTree(nested) {
			t.Error("inConfigCommandTree(deputy proxy config) = true, want false")
		}
	})
}

// executeRootWithConfigErr builds the root command the way Run does, with a
// pending config error, and executes args against it with output discarded.
func executeRootWithConfigErr(t *testing.T, configErr error, args ...string) error {
	t.Helper()
	root := newRoot(configErr)
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	return root.ExecuteContext(context.Background())
}
