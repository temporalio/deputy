package cmd

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	"github.com/temporalio/deputy/internal/license"
)

// Ensure scan-mode enrichment pulls licenses via best-effort sources (e.g., crates.io)
// onto the change set, and that the renderer surfaces them, when deps.dev
// metadata is absent.
func TestEnrichChangeLicenses_ScanUsesBestEffortLicenses(t *testing.T) {
	license.ResetLicenseCachesForTest(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v1/crates/serde/1.0.0") {
			_, _ = w.Write([]byte(`{"version":{"license":"MIT"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	restoreClient := license.WithLicenseHTTPClient(server.Client())
	defer restoreClient()
	restoreBases := license.WithLicenseEndpoints(server.URL, server.URL, server.URL, server.URL, server.URL, server.URL)
	defer restoreBases()

	changes := []*diffv1.PackageChange{{Package: &dependencyv1.Package{Name: "serde", Version: "1.0.0", Ecosystem: "rust"}, ChangeKind: diffv1.ChangeKind_CHANGE_KIND_ADDED, TargetVersion: "1.0.0", IsDirect: true}}

	enriched := enrichChangeLicenses(t.Context(), changes, "scan")
	if len(enriched) != 1 || len(enriched[0].GetPackage().GetLicenses()) == 0 || enriched[0].GetPackage().GetLicenses()[0] != "MIT" {
		t.Fatalf("expected enrichment to attach MIT license, got: %+v", enriched)
	}

	var buf bytes.Buffer
	displayDetailedDependencyChanges(enriched, &buf)

	out := buf.String()
	if !strings.Contains(out, "MIT") {
		t.Fatalf("expected best-effort license to appear in output, got: %s", out)
	}
}

// TestEnrichChangeLicenses_DoesNotInheritRepositoryLicense pins the boundary
// between a project's own license and its dependencies'. Repository license
// files describe the analyzed project; attaching them to dependencies would
// make every change inherit the scanned repo's license, and because these
// values feed policy evaluation, an unknown-license rule would silently pass
// for a dependency that declares nothing.
func TestEnrichChangeLicenses_DoesNotInheritRepositoryLicense(t *testing.T) {
	license.ResetLicenseCachesForTest(t)

	// Registry lookups find nothing, so any license appearing on the change
	// could only have come from the repository scan.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()
	restoreClient := license.WithLicenseHTTPClient(server.Client())
	defer restoreClient()
	restoreBases := license.WithLicenseEndpoints(server.URL, server.URL, server.URL, server.URL, server.URL, server.URL)
	defer restoreBases()

	changes := []*diffv1.PackageChange{{
		Package:       &dependencyv1.Package{Name: "example.com/unlicensed", Version: "1.0.0", Ecosystem: "go"},
		ChangeKind:    diffv1.ChangeKind_CHANGE_KIND_ADDED,
		TargetVersion: "1.0.0",
	}}

	for _, source := range []string{"scan", "both"} {
		t.Run(source, func(t *testing.T) {
			enriched := enrichChangeLicenses(t.Context(), changes, source)
			if len(enriched) != 1 {
				t.Fatalf("expected 1 change, got %d", len(enriched))
			}
			if got := enriched[0].GetPackage().GetLicenses(); len(got) != 0 {
				t.Errorf("dependency inherited licenses it does not declare: %v", got)
			}
		})
	}
}
