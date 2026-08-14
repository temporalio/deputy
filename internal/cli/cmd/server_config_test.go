package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestLoadServerConfig pins that a config file which cannot be loaded stops the
// server instead of downgrading it to defaults. Silently ignoring the file would
// bind a different address and drop the configured TLS settings, which is the
// opposite of what an operator who wrote the file expects.
func TestLoadServerConfig(t *testing.T) {
	tests := []struct {
		name       string
		writeFile  bool
		contents   string
		wantErr    bool
		wantErrHas string
		wantAddr   string
	}{
		{
			name:      "no config file uses defaults",
			writeFile: false,
			wantAddr:  "127.0.0.1:8090",
		},
		{
			name:      "config file address is honored",
			writeFile: true,
			contents:  "server:\n  addr: \"127.0.0.1:9999\"\n",
			wantAddr:  "127.0.0.1:9999",
		},
		{
			name:       "unparseable config is an error",
			writeFile:  true,
			contents:   "server:\n  addr: \"unclosed\n   bogus: [1, 2\n",
			wantErr:    true,
			wantErrHas: "failed to load config from",
		},
		{
			name:       "invalid value is an error",
			writeFile:  true,
			contents:   "logging:\n  level: shouty\n",
			wantErr:    true,
			wantErrHas: "validation failed for logging.level",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Isolate discovery: the temp dir is both the working directory
			// and HOME, and DEPUTY_CONFIG is cleared, so only the fixture can
			// be found.
			dir := t.TempDir()
			t.Setenv("HOME", dir)
			t.Setenv("DEPUTY_CONFIG", "")
			t.Setenv("DEPUTY_LOG_LEVEL", "")
			t.Chdir(dir)

			if test.writeFile {
				if err := os.WriteFile(".deputy.yaml", []byte(test.contents), 0o644); err != nil {
					t.Fatalf("write .deputy.yaml: %v", err)
				}
			}

			// A bare command is enough: loadServerConfig only asks whether
			// flags were changed, and pflag reports false for flags that were
			// never registered.
			cfg, err := loadServerConfig(&serverFlags{}, &cobra.Command{})

			if test.wantErr {
				if err == nil {
					t.Fatalf("loadServerConfig() error = nil, want an error; cfg = %+v", cfg)
				}
				if !strings.Contains(err.Error(), test.wantErrHas) {
					t.Errorf("error %q does not contain %q", err.Error(), test.wantErrHas)
				}
				return
			}

			if err != nil {
				t.Fatalf("loadServerConfig() error = %v, want nil", err)
			}
			if cfg.Addr != test.wantAddr {
				t.Errorf("Addr = %q, want %q", cfg.Addr, test.wantAddr)
			}
		})
	}
}
