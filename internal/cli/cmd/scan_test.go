package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	git "github.com/go-git/go-git/v5"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	analysis "github.com/picatz/deputy/internal/analysis"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/scan"
	"github.com/spf13/cobra"
)

func TestScannerRunScanHonorsEcosystemFilter(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	initGitRepo(t, tmpDir)
	outPath := filepath.Join(tmpDir, "scan.json")

	var captured inv.ScanOptions
	scanner := &Scanner{service: scan.NewServiceWithConfig(&scan.ServiceConfig{
		CollectInventory: func(ctx context.Context, repoPath, gitRef string, opts inv.ScanOptions) ([]*extractor.Package, error) {
			captured = opts
			return []*extractor.Package{
				{Name: "github.com/acme/lib", Version: "v1.0.0", PURLType: purl.TypeGolang},
			}, nil
		},
		QueryVulnerabilities: func(ctx context.Context, client analysis.OSVClient, inputs []analysis.PkgInput) ([]analysis.Vulnerability, error) {
			return nil, nil
		},
	})}

	cmd := newScanTestCommand(t)
	mustSetFlag(t, cmd, "ecosystems", "go,npm")
	mustSetFlag(t, cmd, "format", "json")
	mustSetFlag(t, cmd, "output", outPath)

	if err := scanner.runScan(cmd, []string{tmpDir}); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	want := []string{"go", "npm"}
	if !slices.Equal(captured.Ecosystems, want) {
		t.Fatalf("unexpected ecosystems: got %v want %v", captured.Ecosystems, want)
	}
}

func TestScannerRunScanEmitsMultiEcosystemInputs(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	writePackageJSON(t, filepath.Join(tmpDir, "web"))
	initGitRepo(t, tmpDir)
	outPath := filepath.Join(tmpDir, "scan.json")

	goPkg := &extractor.Package{
		Name:      "github.com/acme/lib",
		Version:   "v1.2.3",
		PURLType:  purl.TypeGolang,
		Locations: []string{"go.mod"},
	}
	npmPkg := &extractor.Package{
		Name:      "left-pad",
		Version:   "1.0.0",
		PURLType:  purl.TypeNPM,
		Locations: []string{"web/package-lock.json"},
	}

	var captured []analysis.PkgInput
	scanner := &Scanner{service: scan.NewServiceWithConfig(&scan.ServiceConfig{
		CollectInventory: func(ctx context.Context, repoPath, gitRef string, opts inv.ScanOptions) ([]*extractor.Package, error) {
			return []*extractor.Package{goPkg, npmPkg}, nil
		},
		QueryVulnerabilities: func(ctx context.Context, client analysis.OSVClient, inputs []analysis.PkgInput) ([]analysis.Vulnerability, error) {
			captured = append([]analysis.PkgInput(nil), inputs...)
			return nil, nil
		},
	})}

	cmd := newScanTestCommand(t)
	mustSetFlag(t, cmd, "ecosystems", "go,npm")
	mustSetFlag(t, cmd, "format", "json")
	mustSetFlag(t, cmd, "output", outPath)

	if err := scanner.runScan(cmd, []string{tmpDir}); err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if len(captured) != 2 {
		t.Fatalf("expected 2 pkg inputs, got %d", len(captured))
	}
	gotEcos := map[string]string{}
	for _, in := range captured {
		gotEcos[in.Name] = in.Ecosystem
	}
	if gotEcos["github.com/acme/lib"] != "Go" {
		t.Fatalf("expected Go ecosystem for module, got %q", gotEcos["github.com/acme/lib"])
	}
	if gotEcos["left-pad"] != "npm" {
		t.Fatalf("expected npm ecosystem for left-pad, got %q", gotEcos["left-pad"])
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
