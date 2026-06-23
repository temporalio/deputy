package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"testing"

	git "github.com/go-git/go-git/v5"

	"github.com/spf13/cobra"
	"github.com/temporalio/deputy/internal/services"
)

// TestRunScanBasicExecution tests that a scan can run successfully on a test directory.
// This is an integration test that uses the real scanning infrastructure.
func TestRunScanBasicExecution(t *testing.T) {
	osvServer := newOSVTestServer(t)
	t.Setenv("DEPUTY_OSV_BASE_URL", osvServer.URL)

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

func newOSVTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []json.RawMessage `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			type minimalResponse struct {
				Vulns []struct {
					ID string `json:"id,omitempty"`
				} `json:"vulns"`
			}

			results := make([]minimalResponse, len(req.Queries))
			for i := range results {
				results[i] = minimalResponse{Vulns: []struct {
					ID string `json:"id,omitempty"`
				}{}}
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				Results []minimalResponse `json:"results"`
			}{Results: results})
			return

		case r.Method == http.MethodGet && path.Dir(r.URL.Path) == "/v1/vulns":
			id := path.Base(r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(struct {
				ID string `json:"id"`
			}{ID: id})
			return
		}

		http.NotFound(w, r)
	})

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
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
