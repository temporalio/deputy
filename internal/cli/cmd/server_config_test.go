package cmd

import (
	"os"
	"slices"
	"testing"

	"github.com/spf13/cobra"
	"github.com/temporalio/deputy/internal/config"
)

// TestLoadServerConfig pins how the server settles its settings: on the
// configuration the CLI already merged, with its own flags on top.
//
// It used to load the config file a second time here. That second load could
// not see the overrides the first one was given, so it answered the same
// question differently, and 'deputy server --log-level=debug' was rejected by
// an invalid DEPUTY_LOG_LEVEL that the flag had already corrected. The
// "not re-read" cases below are what stops that coming back.
func TestLoadServerConfig(t *testing.T) {
	tests := []struct {
		name string
		// onDiskFile is a .deputy.yaml planted in the working directory. It is
		// never the source of the answer; it is there to fail the test if
		// something reads it.
		onDiskFile string
		// supplied is the configuration the CLI merged and handed over.
		supplied *config.Config
		args     []string
		wantAddr string
		// wantCIDRs is checked only when non-nil.
		wantCIDRs []string
	}{
		{
			name:     "no configuration uses the built-in defaults",
			wantAddr: "127.0.0.1:8090",
		},
		{
			name:     "the supplied address is honored",
			supplied: &config.Config{Server: config.ServerConfig{Addr: "127.0.0.1:9999"}},
			wantAddr: "127.0.0.1:9999",
		},
		{
			name:     "a flag outranks the supplied address",
			supplied: &config.Config{Server: config.ServerConfig{Addr: "127.0.0.1:9999"}},
			args:     []string{"--addr", "127.0.0.1:7777"},
			wantAddr: "127.0.0.1:7777",
		},
		{
			name: "the supplied egress allowlist is honored",
			supplied: &config.Config{Server: config.ServerConfig{
				Egress: &config.ServerEgressConfig{AllowedCIDRs: []string{"172.16.0.0/12"}},
			}},
			wantAddr:  "127.0.0.1:8090",
			wantCIDRs: []string{"172.16.0.0/12"},
		},
		{
			name: "an egress flag replaces the supplied allowlist",
			supplied: &config.Config{Server: config.ServerConfig{
				Egress: &config.ServerEgressConfig{AllowedCIDRs: []string{"172.16.0.0/12"}},
			}},
			args:      []string{"--egress-allow-cidr", "10.0.0.0/8"},
			wantAddr:  "127.0.0.1:8090",
			wantCIDRs: []string{"10.0.0.0/8"},
		},
		{
			// A second load would read this file and reject it. The supplied
			// configuration is the answer, so the file on disk is irrelevant.
			name:       "a broken file on disk is not re-read",
			onDiskFile: "logging:\n  level: shouty\n",
			supplied:   &config.Config{Server: config.ServerConfig{Addr: "127.0.0.1:9999"}},
			wantAddr:   "127.0.0.1:9999",
		},
		{
			// The same for a file that cannot be parsed at all, which is the
			// louder half of the same mistake.
			name:       "an unparseable file on disk is not re-read",
			onDiskFile: "server:\n  addr: \"unclosed\n   bogus: [1, 2\n",
			supplied:   &config.Config{Server: config.ServerConfig{Addr: "127.0.0.1:9999"}},
			wantAddr:   "127.0.0.1:9999",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Isolate discovery: the temp dir is both the working directory
			// and HOME, and DEPUTY_CONFIG is cleared, so only the fixture
			// could be found by anything that went looking.
			dir := t.TempDir()
			t.Setenv("HOME", dir)
			t.Setenv("DEPUTY_CONFIG", "")
			t.Setenv("DEPUTY_LOG_LEVEL", "")
			t.Chdir(dir)

			if test.onDiskFile != "" {
				if err := os.WriteFile(".deputy.yaml", []byte(test.onDiskFile), 0o644); err != nil {
					t.Fatalf("write .deputy.yaml: %v", err)
				}
			}

			cmd, flags := newServerCommand(&Dependencies{Config: test.supplied})
			if err := cmd.ParseFlags(test.args); err != nil {
				t.Fatalf("ParseFlags(%v): %v", test.args, err)
			}

			cfg, err := loadServerConfig(flags, cmd, test.supplied)
			if err != nil {
				t.Fatalf("loadServerConfig() error = %v, want nil", err)
			}
			if cfg.Addr != test.wantAddr {
				t.Errorf("Addr = %q, want %q", cfg.Addr, test.wantAddr)
			}
			if test.wantCIDRs != nil {
				var got []string
				if cfg.Egress != nil {
					got = cfg.Egress.AllowedCIDRs
				}
				if !slices.Equal(got, test.wantCIDRs) {
					t.Errorf("Egress.AllowedCIDRs = %v, want %v", got, test.wantCIDRs)
				}
			}
		})
	}
}

// TestAddServerCommand pins that the command the CLI registers is the one the
// precedence tests build, so newServerCommand cannot drift away from the
// shipped surface without failing here.
func TestAddServerCommand(t *testing.T) {
	root := &cobra.Command{Use: "deputy"}
	AddServerCommand(root, &Dependencies{})

	cmd, _, err := root.Find([]string{"server"})
	if err != nil {
		t.Fatalf("Find(server): %v", err)
	}
	if cmd.Name() != "server" {
		t.Fatalf("Find(server) resolved to %q", cmd.Name())
	}
	for _, name := range []string{"addr", "egress-allow-cidr", "egress-allow-host"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("registered server command has no --%s flag", name)
		}
	}
}
