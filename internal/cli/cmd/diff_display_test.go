package cmd

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	analysis "github.com/picatz/deputy/internal/analysis"
	cmp "github.com/picatz/deputy/internal/compare"
)

// Ensure scan-mode enrichment pulls licenses via best-effort sources (e.g., crates.io)
// and surfaces them in the diff output when deps.dev metadata is absent.
func TestDisplayDetailedDependencyChanges_ScanUsesBestEffortLicenses(t *testing.T) {
	analysis.ResetLicenseCachesForTest(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v1/crates/serde/1.0.0") {
			_, _ = w.Write([]byte(`{"version":{"license":"MIT"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	restoreClient := analysis.WithLicenseHTTPClient(server.Client())
	defer restoreClient()
	restoreBases := analysis.WithLicenseEndpoints(server.URL, server.URL, server.URL, server.URL, server.URL, server.URL)
	defer restoreBases()

	changes := []cmp.Change{{
		Name:          "serde",
		TargetVersion: "1.0.0",
		ChangeType:    cmp.Added,
		Ecosystem:     "rust",
		IsDirect:      true,
	}}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	displayDetailedDependencyChanges(context.Background(), nil, changes, true, "scan")

	_ = w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	out := buf.String()
	if !strings.Contains(out, "MIT") {
		t.Fatalf("expected best-effort license to appear in output, got: %s", out)
	}
}
