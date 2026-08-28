package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

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

// writeGoModFixture gives the isolated directory a minimal Go module, so a
// gated command such as "list" has something real to enumerate and can only
// fail for reasons the test is actually about.
func writeGoModFixture(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/fixture\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatalf("write go.mod fixture: %v", err)
	}
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
// cannot be read or parsed is an error the caller must treat as fatal. The
// silent-nil behavior this replaces let a broken file silently swap the
// configured advisory sources, OTel settings, and egress relaxations for the
// defaults, with no diagnostic at all.
//
// A value that merges cleanly but fails validation is deliberately not an error
// here. It cannot be judged yet, because a flag may replace it; the gate does
// that once the command line is parsed, and TestConfigGate covers it.
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
			wantErrHas:        []string{"failed to load config", ".deputy.yaml", "failed to parse config file"},
			wantSuggestionHas: "deputy config validate",
		},
		{
			// The value is carried, not judged. Judging it here would judge it
			// without the flags, which is the ordering this split exists to
			// fix.
			name:      "valid yaml with an invalid value merges and waits for the gate",
			writeFile: true,
			contents:  "logging:\n  level: shouty\n",
			checkConfig: func(t *testing.T, cfg *config.Config) {
				if cfg.Logging.Level != "shouty" {
					t.Errorf("Logging.Level = %q, want the file's value carried through", cfg.Logging.Level)
				}
			},
		},
		{
			name:      "invalid environment value merges and waits for the gate",
			writeFile: false,
			env:       map[string]string{"DEPUTY_LOG_LEVEL": "shouty"},
			checkConfig: func(t *testing.T, cfg *config.Config) {
				if cfg.Logging.Level != "shouty" {
					t.Errorf("Logging.Level = %q, want the environment's value carried through", cfg.Logging.Level)
				}
			},
		},
		{
			name:      "valid config is loaded and honored",
			writeFile: true,
			contents: "logging:\n  level: debug\negress:\n  allow_loopback: true\n" +
				"advisory_sources:\n  - url: \"https://advisories.example.com\"\n",
			checkConfig: func(t *testing.T, cfg *config.Config) {
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

			rc := loadRuntimeConfig()

			if test.wantErr {
				if rc.Err == nil {
					t.Fatalf("loadRuntimeConfig() Err = nil, want an error; Config = %+v", rc.Config)
				}
				if rc.Config != nil {
					t.Errorf("loadRuntimeConfig() returned a config alongside an error: %+v", rc.Config)
				}
				for _, want := range test.wantErrHas {
					if !strings.Contains(rc.Err.Error(), want) {
						t.Errorf("error %q does not contain %q", rc.Err.Error(), want)
					}
				}
				if got := deputyerrors.GetSuggestion(rc.Err); !strings.Contains(got, test.wantSuggestionHas) {
					t.Errorf("suggestion = %q, want it to contain %q", got, test.wantSuggestionHas)
				}
				return
			}

			if rc.Err != nil {
				t.Fatalf("loadRuntimeConfig() Err = %v, want nil", rc.Err)
			}
			if rc.Config == nil {
				t.Fatal("loadRuntimeConfig() returned neither a config nor an error")
			}
			test.checkConfig(t, rc.Config)
		})
	}
}

// TestConfigLoadErrorAttribution pins where the diagnostic points. A merged
// configuration is validated after the environment and flags are folded in, so
// a validation failure cannot be pinned on the file just because a file exists.
// Getting this wrong is worse than saying nothing: it sends the operator to
// 'deputy config validate', which passes on the file it names.
func TestConfigLoadErrorAttribution(t *testing.T) {
	parseFailure := &deputyerrors.ConfigError{
		Path:    ".deputy.yaml",
		Message: "failed to parse config file",
	}
	validationFailure := &deputyerrors.ValidationError{
		Field:   "logging.level",
		Value:   "shouty",
		Message: "must be one of: debug, info, warn, error",
	}

	tests := []struct {
		name              string
		configPath        string
		err               error
		wantErrHas        string
		wantSuggestionHas string
		// wantSuggestionLacks catches the misattribution directly.
		wantSuggestionLacks string
	}{
		{
			name:              "unreadable file blames the file",
			configPath:        ".deputy.yaml",
			err:               parseFailure,
			wantErrHas:        "failed to load config",
			wantSuggestionHas: "deputy config validate .deputy.yaml",
		},
		{
			name:                "validation with a file names both sources",
			configPath:          ".deputy.yaml",
			err:                 validationFailure,
			wantErrHas:          "invalid configuration",
			wantSuggestionHas:   "check both",
			wantSuggestionLacks: "deputy config validate",
		},
		{
			name:                "validation without a file blames the environment",
			configPath:          "",
			err:                 validationFailure,
			wantErrHas:          "invalid configuration",
			wantSuggestionHas:   "DEPUTY_* environment variables",
			wantSuggestionLacks: "deputy config validate",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := configLoadError(test.configPath, test.err)

			if !strings.Contains(got.Error(), test.wantErrHas) {
				t.Errorf("error %q does not contain %q", got.Error(), test.wantErrHas)
			}
			if !errors.Is(got, test.err) {
				t.Errorf("error %v does not wrap the cause %v", got, test.err)
			}
			suggestion := deputyerrors.GetSuggestion(got)
			if !strings.Contains(suggestion, test.wantSuggestionHas) {
				t.Errorf("suggestion %q does not contain %q", suggestion, test.wantSuggestionHas)
			}
			if test.wantSuggestionLacks != "" && strings.Contains(suggestion, test.wantSuggestionLacks) {
				t.Errorf("suggestion %q must not contain %q: the named command passes and teaches nothing", suggestion, test.wantSuggestionLacks)
			}
		})
	}
}

// TestLoadRuntimeConfigExplicitPath covers DEPUTY_CONFIG, which names one
// specific file. Discovery treats an unusable explicit path as a cue to look
// elsewhere, which reintroduces the exact downgrade this package guards
// against: the operator names a file, does not get it, and is told nothing.
func TestLoadRuntimeConfigExplicitPath(t *testing.T) {
	const pinnedSource = "https://advisories.example.com"
	explicit := "advisory_sources:\n  - url: \"" + pinnedSource + "\"\n"

	tests := []struct {
		name string
		// explicitExists writes the file DEPUTY_CONFIG points at.
		explicitExists bool
		// discoverable writes a different .deputy.yaml in the working
		// directory, which discovery would otherwise silently substitute.
		discoverable bool
		wantErr      bool
		wantErrHas   string
	}{
		{
			name:           "explicit path that exists is loaded",
			explicitExists: true,
		},
		{
			name:       "missing explicit path is an error",
			wantErr:    true,
			wantErrHas: "DEPUTY_CONFIG is unavailable",
		},
		{
			name:         "missing explicit path is an error even when another config is discoverable",
			discoverable: true,
			wantErr:      true,
			wantErrHas:   "DEPUTY_CONFIG is unavailable",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := isolatedConfigDir(t)
			explicitPath := filepath.Join(dir, "explicit.yaml")
			if test.explicitExists {
				if err := os.WriteFile(explicitPath, []byte(explicit), 0o644); err != nil {
					t.Fatalf("write explicit config: %v", err)
				}
			}
			if test.discoverable {
				writeConfigFile(t, "logging:\n  level: debug\n")
			}
			t.Setenv("DEPUTY_CONFIG", explicitPath)

			rc := loadRuntimeConfig()

			if test.wantErr {
				if rc.Err == nil {
					t.Fatalf("loadRuntimeConfig() Err = nil, want an error; Config = %+v", rc.Config)
				}
				if !strings.Contains(rc.Err.Error(), test.wantErrHas) {
					t.Errorf("error %q does not contain %q", rc.Err.Error(), test.wantErrHas)
				}
				if got := deputyerrors.GetSuggestion(rc.Err); !strings.Contains(got, "DEPUTY_CONFIG") {
					t.Errorf("suggestion = %q, want it to mention DEPUTY_CONFIG", got)
				}
				return
			}

			if rc.Err != nil {
				t.Fatalf("loadRuntimeConfig() Err = %v, want nil", rc.Err)
			}
			if len(rc.Config.AdvisorySources) != 1 || rc.Config.AdvisorySources[0].URL != pinnedSource {
				t.Errorf("AdvisorySources = %+v, want the source pinned by the explicit file", rc.Config.AdvisorySources)
			}
		})
	}
}

// TestFlagOverrides pins what the gate hands to configuration: every flag the
// invocation set, by name, and nothing it did not set. Reporting a chosen few
// is what left command-specific flags out of the validated merge, so the test
// covers a repeatable flag from a subcommand alongside the root's own.
func TestFlagOverrides(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want config.Overrides
	}{
		{
			name: "no flags",
			args: []string{"list", "."},
			want: config.Overrides{},
		},
		{
			name: "equals form",
			args: []string{"list", ".", "--log-level=debug"},
			want: config.Overrides{"log-level": {"debug"}},
		},
		{
			name: "space form",
			args: []string{"list", ".", "--log-level", "debug"},
			want: config.Overrides{"log-level": {"debug"}},
		},
		{
			name: "before the subcommand",
			args: []string{"--log-level", "debug", "list", "."},
			want: config.Overrides{"log-level": {"debug"}},
		},
		{
			name: "both logging flags",
			args: []string{"scan", "--log-level=warn", "--log-format=json"},
			want: config.Overrides{"log-level": {"warn"}, "log-format": {"json"}},
		},
		{
			// A repeatable flag on a subcommand: the one shape the old scrape
			// could not see, and the one that made an invalid config file
			// unstartable even when the command line replaced the bad value.
			name: "repeatable subcommand flag keeps every value",
			args: []string{"server", "--egress-allow-cidr", "10.0.0.0/8", "--egress-allow-cidr", "192.168.0.0/16"},
			want: config.Overrides{"egress-allow-cidr": {"10.0.0.0/8", "192.168.0.0/16"}},
		},
		{
			// The inner flag belongs to npm, not to Deputy. Reading it would
			// let an unrelated argument satisfy Deputy's config validation.
			name: "nothing after the terminator is a flag",
			args: []string{"proxy", "npm", "--", "npm", "install", "--log-level=silly"},
			want: config.Overrides{},
		},
		{
			name: "an explicitly empty flag is reported as set",
			args: []string{"list", "--log-level="},
			want: config.Overrides{"log-level": {""}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := flagOverrides(resolveCommand(t, runtimeConfig{}, test.args...))
			if !maps.EqualFunc(got, test.want, slices.Equal) {
				t.Errorf("flagOverrides(%v) = %v, want %v", test.args, got, test.want)
			}
		})
	}
}

// TestOverrideFlagNamesAreRealFlags checks the override registry against the
// commands the CLI actually ships. An override keyed on a flag that was renamed
// or removed stops applying without a word, and the config file value it existed
// to correct starts winning again, which is the defect this whole gate is about
// arriving by a different route.
func TestOverrideFlagNamesAreRealFlags(t *testing.T) {
	names := config.OverrideFlagNames()
	if len(names) == 0 {
		t.Fatal("config.OverrideFlagNames() is empty; the checks below would pass vacuously")
	}

	root := newRoot(runtimeConfig{})
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			if !declaresFlag(root, name) {
				t.Errorf("configuration overrides --%s, which no command declares, so the override can never apply", name)
			}
		})
	}
}

// declaresFlag reports whether cmd or any command beneath it declares a flag of
// this name, local or persistent.
func declaresFlag(cmd *cobra.Command, name string) bool {
	if cmd.Flags().Lookup(name) != nil || cmd.PersistentFlags().Lookup(name) != nil {
		return true
	}
	return slices.ContainsFunc(cmd.Commands(), func(child *cobra.Command) bool {
		return declaresFlag(child, name)
	})
}

// TestConfigGate pins the ordering the three round-two findings all came from:
// configuration is judged against the values the command will use, so a flag
// can correct what the environment or the file got wrong, and cannot rescue
// what it does not replace. Validating before the command line was parsed made
// every override-capable flag a separate defect, one per flag.
func TestConfigGate(t *testing.T) {
	// badCIDRFile is the finding that command-specific flags exposed: only the
	// server command can replace this value, so only the server command's flags
	// can tell whether it is the effective one.
	const badCIDRFile = "server:\n  egress:\n    allowed_cidrs:\n      - \"not-a-cidr\"\n"
	const badLevelFile = "logging:\n  level: shouty\n"

	tests := []struct {
		name        string
		file        string
		env         map[string]string
		args        []string
		wantRefused bool
		wantErrHas  string
	}{
		{
			name:        "an invalid file CIDR stops the server",
			file:        badCIDRFile,
			args:        []string{"server"},
			wantRefused: true,
			wantErrHas:  "server.egress.allowed_cidrs",
		},
		{
			name: "a valid egress flag corrects an invalid file CIDR",
			file: badCIDRFile,
			args: []string{"server", "--egress-allow-cidr", "10.0.0.0/8"},
		},
		{
			name:        "an invalid egress flag is rejected on its own terms",
			file:        badCIDRFile,
			args:        []string{"server", "--egress-allow-cidr", "also-not-a-cidr"},
			wantRefused: true,
			wantErrHas:  "server.egress.allowed_cidrs",
		},
		{
			name:        "an invalid environment level stops a gated command",
			env:         map[string]string{"DEPUTY_LOG_LEVEL": "shouty"},
			args:        []string{"list", "."},
			wantRefused: true,
			wantErrHas:  "logging.level",
		},
		{
			name: "a logging flag corrects an invalid environment level",
			env:  map[string]string{"DEPUTY_LOG_LEVEL": "shouty"},
			args: []string{"list", ".", "--log-level=debug"},
		},
		{
			// The server command reached its own second load here, which had
			// none of the overrides, and rejected a flag the root accepted.
			name: "a logging flag corrects an invalid environment level for the server too",
			env:  map[string]string{"DEPUTY_LOG_LEVEL": "shouty"},
			args: []string{"server", "--log-level=debug"},
		},
		{
			name: "a logging flag placed before the subcommand still corrects it",
			env:  map[string]string{"DEPUTY_LOG_LEVEL": "shouty"},
			args: []string{"--log-level", "debug", "list", "."},
		},
		{
			name: "a logging flag corrects an invalid file level",
			file: badLevelFile,
			args: []string{"scan", ".", "--log-level=debug"},
		},
		{
			name:        "an explicitly empty flag chooses nothing and does not correct",
			env:         map[string]string{"DEPUTY_LOG_LEVEL": "shouty"},
			args:        []string{"list", ".", "--log-level="},
			wantRefused: true,
			wantErrHas:  "logging.level",
		},
		{
			name:        "a flag for a different field does not correct",
			env:         map[string]string{"DEPUTY_LOG_LEVEL": "shouty"},
			args:        []string{"list", ".", "--log-format=json"},
			wantRefused: true,
			wantErrHas:  "logging.level",
		},
		{
			name:        "a passthrough argument cannot pose as a correcting flag",
			env:         map[string]string{"DEPUTY_LOG_LEVEL": "shouty"},
			args:        []string{"proxy", "npm", "--", "npm", "install", "--log-level=debug"},
			wantRefused: true,
			wantErrHas:  "logging.level",
		},
		{
			// No flag can correct a file the loader never read.
			name:        "an unparseable file is refused whatever the flags say",
			file:        "logging:\n  level: \"unclosed\n   bogus: [1, 2\n",
			args:        []string{"list", ".", "--log-level=debug"},
			wantRefused: true,
			wantErrHas:  "failed to parse config file",
		},
		{
			name: "a valid configuration passes",
			file: "logging:\n  level: debug\n",
			args: []string{"list", "."},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isolatedConfigDir(t)
			if test.file != "" {
				writeConfigFile(t, test.file)
			}
			for k, v := range test.env {
				t.Setenv(k, v)
			}

			rc := loadRuntimeConfig()
			err := configGateError(rc, resolveCommand(t, rc, test.args...))

			if test.wantRefused {
				if err == nil {
					t.Fatalf("configGateError(%v) = nil, want a refusal", test.args)
				}
				if !strings.Contains(err.Error(), test.wantErrHas) {
					t.Errorf("error %q does not contain %q", err.Error(), test.wantErrHas)
				}
				return
			}
			if err != nil {
				t.Errorf("configGateError(%v) = %v, want nil: the invocation replaced the offending value", test.args, err)
			}
		})
	}
}

// resolveCommand builds the real root command and resolves args the way cobra
// does before it calls PersistentPreRunE, so a test sees the command that would
// run with the flag set it would have.
func resolveCommand(t *testing.T, rc runtimeConfig, args ...string) *cobra.Command {
	t.Helper()
	root := newRoot(rc)
	// Help and completion are attached lazily at Execute time.
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()

	cmd, flagArgs, err := root.Find(args)
	if err != nil {
		t.Fatalf("Find(%v): %v", args, err)
	}
	if err := cmd.ParseFlags(flagArgs); err != nil {
		t.Fatalf("ParseFlags(%v): %v", flagArgs, err)
	}
	return cmd
}

// TestRootRefusesUnloadableConfig proves the load failure reaches command
// execution rather than stopping at loadRuntimeConfig: a command must fail
// instead of running on defaults. It drives the root command the way Run does,
// against a real broken file.
func TestRootRefusesUnloadableConfig(t *testing.T) {
	tests := []struct {
		name       string
		contents   string
		wantErrHas string
	}{
		{
			name:       "unparseable yaml",
			contents:   "logging:\n  level: \"unclosed\n   bogus: [1, 2\n",
			wantErrHas: "failed to parse config file",
		},
		{
			name:       "invalid value",
			contents:   "logging:\n  level: shouty\n",
			wantErrHas: "validation failed for logging.level",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			isolatedConfigDir(t)
			writeConfigFile(t, test.contents)

			// "list" is gated (it honors egress and advisory sources), and
			// it is pointed at a directory with nothing to enumerate so the
			// only thing that can fail it is the config gate. Deliberately
			// not "version", which the allowlist exempts.
			err := executeRootFromEnvironment(t, context.Background(), "list", ".")
			if err == nil {
				t.Fatal("command succeeded with an unloadable config; it ran on defaults instead of failing")
			}
			if !isConfigGateError(err) {
				t.Errorf("command error = %v, want the config gate refusal; an incidental error would hide a gate that stopped firing", err)
			}
			if !strings.Contains(err.Error(), test.wantErrHas) {
				t.Errorf("error %q does not contain %q", err.Error(), test.wantErrHas)
			}
		})
	}
}

// TestRootAllowsConfigCommandsWithUnloadableConfig pins the diagnostic
// exemption: the commands that explain a broken config file must stay runnable
// when the file is broken, otherwise the failure message has no follow-up.
func TestRootAllowsConfigCommandsWithUnloadableConfig(t *testing.T) {
	isolatedConfigDir(t)
	writeConfigFile(t, "logging:\n  level: shouty\n")

	if err := executeRootFromEnvironment(t, context.Background(), "config", "path"); err != nil {
		t.Errorf("'config path' failed with an unloadable config: %v", err)
	}
}

// TestRootRunsWithValidConfig guards the other direction, so the gate cannot
// pass by failing everything: a loadable config file leaves a gated command
// runnable. It uses "list", not an exempt command, or it would prove nothing.
func TestRootRunsWithValidConfig(t *testing.T) {
	dir := isolatedConfigDir(t)
	writeGoModFixture(t, dir)
	writeConfigFile(t, "logging:\n  level: debug\n")

	if err := executeRootFromEnvironment(t, context.Background(), "list", "."); err != nil {
		t.Errorf("'list' failed with a valid config: %v", err)
	}
}

// TestRootRunsWithoutConfigFile pins the silent-success case: with no config
// file anywhere, commands run and nothing is written to the command's error
// stream.
func TestRootRunsWithoutConfigFile(t *testing.T) {
	dir := isolatedConfigDir(t)
	writeGoModFixture(t, dir)

	rc := loadRuntimeConfig()
	if rc.Err != nil {
		t.Fatalf("loadRuntimeConfig() Err = %v, want nil for an absent config file", rc.Err)
	}
	if rc.Config == nil {
		t.Fatal("Config is nil for an absent config file")
	}

	var stderr bytes.Buffer
	root := newRoot(rc)
	root.SetArgs([]string{"list", "."})
	root.SetOut(io.Discard)
	root.SetErr(&stderr)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Errorf("'list' failed with no config file: %v", err)
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty: an absent config file must stay silent", stderr.String())
	}
}

// TestRunsWithoutConfig pins the exemption allowlist in both directions: the
// commands that must survive an unloadable config and, just as importantly, the
// ones that must not. A one-sided test would pass just as well if the predicate
// started returning true for everything.
func TestRunsWithoutConfig(t *testing.T) {
	root := newRoot(runtimeConfig{})
	// The help and completion commands are attached lazily at Execute time, so
	// materialize them before looking commands up by name.
	root.InitDefaultHelpCmd()
	root.InitDefaultCompletionCmd()

	find := func(t *testing.T, args ...string) *cobra.Command {
		t.Helper()
		cmd, _, err := root.Find(args)
		if err != nil {
			t.Fatalf("Find(%v): %v", args, err)
		}
		if len(args) > 0 && cmd.Name() != args[len(args)-1] {
			t.Fatalf("Find(%v) resolved to %q, not the command under test", args, cmd.Name())
		}
		return cmd
	}

	tests := []struct {
		name string
		args []string
		want bool
	}{
		// Exempt: these do not act on configuration.
		{name: "config", args: []string{"config"}, want: true},
		{name: "config show", args: []string{"config", "show"}, want: true},
		{name: "config validate", args: []string{"config", "validate"}, want: true},
		{name: "version", args: []string{"version"}, want: true},
		{name: "completion", args: []string{"completion"}, want: true},
		{name: "completion zsh", args: []string{"completion", "zsh"}, want: true},
		{name: "help", args: []string{"help"}, want: true},

		// Gated: each of these honors egress, advisory sources, or otel.
		{name: "root runs diff when bare", args: nil, want: false},
		{name: "list", args: []string{"list"}, want: false},
		{name: "scan", args: []string{"scan"}, want: false},
		{name: "server", args: []string{"server"}, want: false},
		{name: "diff", args: []string{"diff"}, want: false},
		{name: "fix", args: []string{"fix"}, want: false},
		{name: "proxy", args: []string{"proxy"}, want: false},
		{name: "init", args: []string{"init"}, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := runsWithoutConfig(find(t, test.args...)); got != test.want {
				t.Errorf("runsWithoutConfig(%v) = %v, want %v", test.args, got, test.want)
			}
		})
	}

	// Cobra's hidden completion commands are what a shell actually invokes on
	// every tab press, so they matter more than the visible "completion"
	// command and are looked up by their cobra constants.
	// Cobra attaches them to the root at Execute time, which is too late to
	// look up here, so they are reproduced as direct children of a throwaway
	// root exactly as cobra attaches them.
	for _, name := range []string{cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd} {
		t.Run(name, func(t *testing.T) {
			fakeRoot := &cobra.Command{Use: "deputy"}
			hidden := &cobra.Command{Use: name}
			fakeRoot.AddCommand(hidden)
			if !runsWithoutConfig(hidden) {
				t.Errorf("runsWithoutConfig(%s) = false, want true; shell tab completion would error on a broken config", name)
			}
		})
	}

	// The allowlist keys on the top-level command, not on the name alone, so a
	// command that shares an exempt name but hangs off something else must not
	// pick up the exemption.
	t.Run("nested command named config is not exempt", func(t *testing.T) {
		nested := nestedCommand(t, "proxy", "config")
		if runsWithoutConfig(nested) {
			t.Error("runsWithoutConfig(deputy proxy config) = true, want false")
		}
	})
	t.Run("nested command named version is not exempt", func(t *testing.T) {
		nested := nestedCommand(t, "policy", "version")
		if runsWithoutConfig(nested) {
			t.Error("runsWithoutConfig(deputy policy version) = true, want false")
		}
	})
}

// nestedCommand builds a throwaway root -> parent -> child tree and returns the
// child, for checking that an exempt name does not confer the exemption when it
// appears below the top level.
func nestedCommand(t *testing.T, parentName, childName string) *cobra.Command {
	t.Helper()
	root := &cobra.Command{Use: "deputy"}
	parent := &cobra.Command{Use: parentName}
	child := &cobra.Command{Use: childName}
	parent.AddCommand(child)
	root.AddCommand(parent)
	return child
}

// TestRootConfigGateBySource pins exemption as a property that holds across
// every way configuration can be broken, not just the one the gate happens to
// check. An invalid logging value in the environment used to take down the
// exempt commands anyway, because the gate skipped its own error and then
// logging setup failed on the same value: exempt in one branch and not in the
// next is not exempt.
func TestRootConfigGateBySource(t *testing.T) {
	sources := []struct {
		name string
		// apply breaks the configuration in one specific way.
		apply func(t *testing.T)
	}{
		{
			name: "unparseable file",
			apply: func(t *testing.T) {
				writeConfigFile(t, "logging:\n  level: \"unclosed\n   bogus: [1, 2\n")
			},
		},
		{
			name: "invalid value in file",
			apply: func(t *testing.T) {
				writeConfigFile(t, "logging:\n  level: shouty\n")
			},
		},
		{
			name: "invalid value in environment",
			apply: func(t *testing.T) {
				t.Setenv("DEPUTY_LOG_LEVEL", "shouty")
			},
		},
		{
			name: "invalid format in environment",
			apply: func(t *testing.T) {
				t.Setenv("DEPUTY_LOG_FORMAT", "bogus")
			},
		},
		{
			name: "both file and environment broken",
			apply: func(t *testing.T) {
				writeConfigFile(t, "logging:\n  level: shouty\n")
				t.Setenv("DEPUTY_LOG_LEVEL", "alsoshouty")
			},
		},
	}

	commands := []struct {
		name string
		args []string
		// wantRefused is true for commands the gate must stop whatever the
		// source of the breakage.
		wantRefused bool
	}{
		{name: "version", args: []string{"version"}},
		{name: "help", args: []string{"help"}},
		{name: "completion zsh", args: []string{"completion", "zsh"}},
		{name: "config path", args: []string{"config", "path"}},
		{name: "hidden completion", args: []string{cobra.ShellCompRequestCmd, "list", ""}},

		{name: "list", args: []string{"list", "."}, wantRefused: true},
		{name: "diff", args: []string{"diff"}, wantRefused: true},
	}

	for _, source := range sources {
		for _, command := range commands {
			t.Run(source.name+"/"+command.name, func(t *testing.T) {
				isolatedConfigDir(t)
				source.apply(t)

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				err := executeRootFromEnvironment(t, ctx, command.args...)

				if command.wantRefused {
					if !isConfigGateError(err) {
						t.Errorf("%v error = %v, want the config gate refusal; it ran on defaults instead of being refused", command.args, err)
					}
					return
				}
				if err != nil {
					t.Errorf("%v failed with a broken configuration: %v; exempt commands must work in exactly this state", command.args, err)
				}
			})
		}
	}
}

// TestRootConfigGateByCommand runs the real commands against a real broken
// config file, so the allowlist is pinned where it actually takes effect rather
// than only at the predicate. Exempt commands must succeed; gated commands must
// fail with the config error itself, not with some incidental error that would
// mask a gate that stopped firing.
func TestRootConfigGateByCommand(t *testing.T) {
	isolatedConfigDir(t)
	writeConfigFile(t, "logging:\n  level: shouty\n")

	tests := []struct {
		name string
		args []string
		// wantRefused is true for commands the config gate must stop.
		wantRefused bool
	}{
		{name: "version", args: []string{"version"}},
		{name: "completion zsh", args: []string{"completion", "zsh"}},
		{name: "completion bash", args: []string{"completion", "bash"}},
		{name: "help", args: []string{"help"}},
		{name: "help for a gated command", args: []string{"help", "list"}},
		{name: "config path", args: []string{"config", "path"}},
		{name: "hidden completion", args: []string{cobra.ShellCompRequestCmd, "list", ""}},

		{name: "list", args: []string{"list", "."}, wantRefused: true},
		{name: "scan", args: []string{"scan", "."}, wantRefused: true},
		{name: "server", args: []string{"server", "--addr", "127.0.0.1:0"}, wantRefused: true},
		{name: "diff", args: []string{"diff"}, wantRefused: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// A gated command that is wrongly allowed through would otherwise
			// run for real (server blocks forever, scan reaches the network),
			// so bound every case rather than trusting the gate under test.
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			err := executeRootFromEnvironment(t, ctx, test.args...)

			if test.wantRefused {
				if !isConfigGateError(err) {
					t.Errorf("%v error = %v, want the config gate refusal; the command ran on defaults instead of being refused", test.args, err)
				}
				return
			}
			if err != nil {
				t.Errorf("%v failed with an unloadable config: %v; this command must keep working so the failure can be diagnosed", test.args, err)
			}
		})
	}
}

// executeRootFromEnvironment builds the root command the way Run does, from
// whatever configuration the surrounding test fixture provides, and executes
// args against it with output discarded.
//
// It loads for real rather than being handed a prepared error, because the
// configuration a command is judged against is not settled until that command's
// flags are parsed. A test that supplied its own error would decide the outcome
// it was meant to observe.
func executeRootFromEnvironment(t *testing.T, ctx context.Context, args ...string) error {
	t.Helper()
	root := newRoot(loadRuntimeConfig())
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	return root.ExecuteContext(ctx)
}

// isConfigGateError reports whether err is the configuration gate refusing to
// run, rather than an incidental failure from a command that was wrongly let
// through. The gate always wraps the configuration fault it found, so the
// wrapped type is what distinguishes the two.
func isConfigGateError(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := errors.AsType[*deputyerrors.ConfigError](err); ok {
		return true
	}
	_, ok := errors.AsType[*deputyerrors.ValidationError](err)
	return ok
}
