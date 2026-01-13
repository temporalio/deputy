package cmd

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	git "github.com/go-git/go-git/v5"

	"github.com/picatz/deputy/internal/services"
	"github.com/spf13/cobra"
)

// TestRunScanBasicExecution tests that a scan can run successfully on a test directory.
// This is an integration test that uses the real scanning infrastructure.
func TestRunScanBasicExecution(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	initGitRepo(t, tmpDir)
	outPath := filepath.Join(tmpDir, "scan.json")

	cmd := newScanTestCommand(t)
	mustSetFlag(t, cmd, "ecosystems", "go")
	mustSetFlag(t, cmd, "format", "json")
	mustSetFlag(t, cmd, "output", outPath)

	// Use real in-process clients
	c := newScanTestClients(t)

	if err := runScan(c, cmd, []string{tmpDir}); err != nil {
		t.Fatalf("runScan: %v", err)
	}

	// Verify output file was created
	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("output file not created: %v", err)
	}
}

func newScanTestCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	flags := cmd.Flags()
	flags.String("ref", "HEAD", "")
	flags.StringSlice("ecosystems", []string{"all"}, "")
	flags.String("output", "", "")
	flags.String("format", "text", "")
	flags.Bool("ignore-unfixed", false, "")
	flags.String("published-before", "", "")
	flags.String("published-after", "", "")
	flags.String("as-of", "", "")
	flags.String("source", "", "")
	flags.String("platform", "", "")
	return cmd
}

func writeGoModule(t *testing.T, dir string) {
	t.Helper()
	mod := `module example.com/app

go 1.24

require github.com/acme/lib v1.2.3
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(mod), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
}

func writePackageJSON(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	pkgJSON := `{
  "name": "web",
  "dependencies": {
    "left-pad": "1.0.0"
  }
}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSON), 0o600); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write package-lock: %v", err)
	}
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	if _, err := git.PlainInit(dir, false); err != nil {
		t.Fatalf("init git repo: %v", err)
	}
}

func mustSetFlag(t *testing.T, cmd *cobra.Command, name, value string) {
	t.Helper()
	if err := cmd.Flags().Set(name, value); err != nil {
		t.Fatalf("set flag %s: %v", name, err)
	}
}

// newScanTestClients creates a services.Clients for testing using the real in-process handlers.
func newScanTestClients(t *testing.T) *services.Clients {
	t.Helper()

	// Create real services with local mode enabled
	svc, err := services.New()
	if err != nil {
		t.Fatalf("create services: %v", err)
	}

	// Return in-process clients
	return svc.InProcessClients()
}
