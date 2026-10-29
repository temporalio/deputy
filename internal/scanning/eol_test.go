package scanning

import (
	"testing"
	"time"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/analysis/distroeol"
	"github.com/temporalio/deputy/internal/regression"
)

// eolScanDate pins end-of-life verdicts to the dataset snapshot so the
// expectations below do not move with the calendar.
var eolScanDate = time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)

func eolDataset(t *testing.T) *distroeol.Dataset {
	t.Helper()
	ds, err := distroeol.Default()
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

// TestCheckEOLRegressionImages runs the check over recorded public image
// inventories. Each image yields exactly one release, read from its OS package
// metadata, and only the end-of-life ones produce a finding.
func TestCheckEOLRegressionImages(t *testing.T) {
	tests := []struct {
		image                 string
		distribution, release string
		version               string
		status                vulnerabilityv1.DistroStatus
		advisory              string // empty: no finding
		eol                   string
		daysPastEOL           int32
		ecosystem             string
	}{
		{
			// The issue's motivating case: Alpine 3.18 under an application
			// image, scanned with no end-of-life signal before this check.
			image: "base-server-1.15.3", distribution: "alpine", release: "3.18", version: "3.18.3",
			status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_EOL, advisory: "DEPUTY-EOL-ALPINE-3.18",
			eol: "2025-05-09", daysPastEOL: 538, ecosystem: "Alpine:v3.18",
		},
		{
			image: "server-1.20.0", distribution: "alpine", release: "3.17", version: "3.17.1",
			status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_EOL, advisory: "DEPUTY-EOL-ALPINE-3.17",
			eol: "2024-11-22", daysPastEOL: 706, ecosystem: "Alpine:v3.17",
		},
		{image: "alpine-3.24.0", distribution: "alpine", release: "3.24", version: "3.24.0", status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_SUPPORTED},
		{image: "alpine-3.24.1", distribution: "alpine", release: "3.24", version: "3.24.1", status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_SUPPORTED},
		{image: "debian-12-slim", distribution: "debian", release: "12", version: "bookworm", status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_SUPPORTED},
		// Distroless status.d records VERSION_ID rather than a codename.
		{image: "distroless-static-debian12", distribution: "debian", release: "12", version: "12", status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_SUPPORTED},
		{image: "distroless-base-debian12", distribution: "debian", release: "12", version: "12", status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_SUPPORTED},
		{image: "ubuntu-24.04", distribution: "ubuntu", release: "24.04", version: "noble", status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_SUPPORTED},
	}
	ds := eolDataset(t)
	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			img, err := regression.Load(tt.image)
			if err != nil {
				t.Fatal(err)
			}
			got := checkEOL(img.Packages, eolScanDate, ds)
			if len(got.distros) != 1 {
				t.Fatalf("distros = %v, want exactly one", got.distros)
			}
			d := got.distros[0]
			if d.GetDistribution() != tt.distribution || d.GetRelease() != tt.release || d.GetVersion() != tt.version || d.GetStatus() != tt.status {
				t.Errorf("distro = %s %s (%s) %v, want %s %s (%s) %v",
					d.GetDistribution(), d.GetRelease(), d.GetVersion(), d.GetStatus(),
					tt.distribution, tt.release, tt.version, tt.status)
			}
			if d.GetOrigin() != distroeol.OriginOSPackage || d.GetDatasetSnapshot() != "2026-10-29" {
				t.Errorf("origin %q snapshot %q", d.GetOrigin(), d.GetDatasetSnapshot())
			}
			if len(got.warnings) != 0 {
				t.Errorf("warnings = %v", got.warnings)
			}
			if tt.advisory == "" {
				if len(got.findings) != 0 {
					t.Fatalf("supported release produced findings: %+v", got.findings)
				}
				return
			}
			if len(got.findings) != 1 {
				t.Fatalf("findings = %+v, want one", got.findings)
			}
			f := got.findings[0]
			if f.AdvisoryID != tt.advisory || f.Dependency.Ecosystem != tt.ecosystem || f.Version != tt.version || !f.Affected {
				t.Errorf("finding = %+v", f)
			}
			adv := got.advisories[tt.advisory]
			if adv.GetKind() != vulnerabilityv1.FindingKind_FINDING_KIND_EOL {
				t.Errorf("kind = %v, want EOL", adv.GetKind())
			}
			if adv.GetSeverity().GetLevel() != vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH {
				t.Errorf("severity = %v, want HIGH", adv.GetSeverity().GetLevel())
			}
			if p := adv.GetPublished().AsTime().Format(time.DateOnly); p != tt.eol {
				t.Errorf("published = %s, want the eol date %s", p, tt.eol)
			}
			dsp := adv.GetDatabaseSpecific()
			if dsp["eol_date"] != tt.eol || dsp["latest_release"] != "3.24" || dsp["oldest_supported_release"] != "3.21" || dsp["eol_dataset"] != "endoflife.date@2026-10-29" {
				t.Errorf("database_specific = %v", dsp)
			}
			if d.GetDaysPastEol() != tt.daysPastEOL {
				t.Errorf("days_past_eol = %d, want %d", d.GetDaysPastEol(), tt.daysPastEOL)
			}
		})
	}
}

// TestCheckEOLImageRefs covers directory scans, where the release comes from
// a container image reference such as a Dockerfile FROM line. Each reference
// gets its own record and finding, attributed to the reference's package and
// location so a suppression or fix lands on the right line.
func TestCheckEOLImageRefs(t *testing.T) {
	ds := eolDataset(t)
	pkgs := []*dependencyv1.Package{
		{Name: "library/alpine", Version: "3.18", Ecosystem: "docker", Purl: "pkg:docker/library%2Falpine@3.18", Direct: true, Locations: []string{"Dockerfile"}},
		{Name: "gcr.io/distroless/static-debian11", Version: "latest", Ecosystem: "oci", Purl: "pkg:oci/gcr.io%2Fdistroless%2Fstatic-debian11@latest", Direct: true, Locations: []string{"build/Dockerfile"}},
		{Name: "library/node", Version: "20-bookworm-slim", Ecosystem: "docker", Purl: "pkg:docker/library%2Fnode@20-bookworm-slim", Direct: true, Locations: []string{"Dockerfile"}},
		// Names no release: nothing recorded.
		{Name: "library/alpine", Version: "latest", Ecosystem: "docker", Purl: "pkg:docker/library%2Falpine@latest", Direct: true, Locations: []string{"Dockerfile"}},
	}
	got := checkEOL(pkgs, eolScanDate, ds)
	if len(got.distros) != 3 {
		t.Fatalf("distros = %v, want 3", got.distros)
	}
	ids := map[string]string{}
	for _, f := range got.findings {
		ids[f.AdvisoryID] = f.Locations[0] + " " + f.Dependency.Name
		if !f.Direct {
			t.Errorf("%s: an image named in a Dockerfile is direct", f.AdvisoryID)
		}
	}
	want := map[string]string{
		"DEPUTY-EOL-ALPINE-3.18": "Dockerfile library/alpine",
		"DEPUTY-EOL-DEBIAN-11":   "build/Dockerfile gcr.io/distroless/static-debian11",
	}
	if len(ids) != len(want) {
		t.Fatalf("findings = %v, want %v", ids, want)
	}
	for id, w := range want {
		if ids[id] != w {
			t.Errorf("%s at %q, want %q", id, ids[id], w)
		}
	}
	if s := got.distros[0].GetSubject(); s != "library/alpine:3.18" {
		t.Errorf("subject = %q", s)
	}
}

// TestCheckEOLUnknownDistributionWarns pins the honesty rule: an untracked
// distribution is reported as unknown, with a warning, and never as supported.
func TestCheckEOLUnknownDistributionWarns(t *testing.T) {
	got := checkEOL([]*dependencyv1.Package{
		{Name: "bash", Version: "5.2", Ecosystem: "Red Hat", Purl: "pkg:rpm/redhat/bash@5.2?distro=rhel-9.4"},
	}, eolScanDate, eolDataset(t))
	if len(got.findings) != 0 || len(got.distros) != 1 || got.distros[0].GetStatus() != vulnerabilityv1.DistroStatus_DISTRO_STATUS_UNKNOWN {
		t.Fatalf("got findings %v distros %v", got.findings, got.distros)
	}
	if len(got.warnings) != 1 {
		t.Fatalf("warnings = %v, want one", got.warnings)
	}
}
