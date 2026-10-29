package distroeol

import (
	"testing"
	"time"

	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

// scanDate pins every verdict in these tests to the dataset snapshot.
var scanDate = time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)

func dataset(t *testing.T) *Dataset {
	t.Helper()
	ds, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	return ds
}

func TestDefaultDatasetRecordsSnapshot(t *testing.T) {
	ds := dataset(t)
	if ds.Snapshot != "2026-10-29" {
		t.Errorf("Snapshot = %q, want 2026-10-29", ds.Snapshot)
	}
	for _, d := range []string{"alpine", "debian", "ubuntu"} {
		if !ds.Knows(d) {
			t.Errorf("dataset does not know %s", d)
		}
	}
}

func TestParseRejectsBadSnapshot(t *testing.T) {
	if _, err := Parse([]byte(`{"snapshot":"yesterday","distributions":{}}`)); err == nil {
		t.Fatal("Parse accepted a snapshot that is not a date")
	}
}

func TestFromOSPackage(t *testing.T) {
	tests := []struct {
		purl string
		want Identity
		ok   bool
	}{
		{"pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=3.18.12", Identity{"alpine", "3.18", "3.18.12", OriginOSPackage}, true},
		{"pkg:apk/alpine/musl@1.2.5-r0?arch=x86_64&distro=3.25.0_alpha20260101", Identity{"alpine", "edge", "3.25.0_alpha20260101", OriginOSPackage}, true},
		{"pkg:deb/debian/libc6@2.36-9?arch=amd64&distro=bookworm", Identity{"debian", "bookworm", "bookworm", OriginOSPackage}, true},
		// Distroless status.d records VERSION_ID, not a codename.
		{"pkg:deb/debian/libssl3@3.0.20-1~deb12u2?arch=amd64&distro=12&source=openssl", Identity{"debian", "12", "12", OriginOSPackage}, true},
		{"pkg:deb/debian/libc6@2.31-13?distro=debian-11", Identity{"debian", "11", "11", OriginOSPackage}, true},
		{"pkg:deb/ubuntu/apt@2.8.3?arch=amd64&distro=noble", Identity{"ubuntu", "noble", "noble", OriginOSPackage}, true},
		{"pkg:rpm/fedora/bash@5.2?distro=fedora-40", Identity{"fedora", "40", "40", OriginOSPackage}, true},
		{"pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64", Identity{}, false},
		{"pkg:golang/golang.org/x/net@v0.1.0", Identity{}, false},
	}
	for _, tt := range tests {
		got, ok := FromOSPackage(tt.purl)
		if ok != tt.ok || got != tt.want {
			t.Errorf("FromOSPackage(%q) = %+v, %v; want %+v, %v", tt.purl, got, ok, tt.want, tt.ok)
		}
	}
}

func TestFromImageRef(t *testing.T) {
	ds := dataset(t)
	tests := []struct {
		purl                  string
		distribution, release string
		ok                    bool
	}{
		{"pkg:docker/library%2Falpine@3.18", "alpine", "3.18", true},
		{"pkg:docker/library/alpine@3.18.4", "alpine", "3.18", true},
		{"pkg:docker/alpine@3.21", "alpine", "3.21", true},
		{"pkg:docker/library%2Fdebian@bookworm-slim", "debian", "bookworm", true},
		{"pkg:docker/library%2Fdebian@12.4-slim", "debian", "12", true},
		{"pkg:docker/library%2Fubuntu@jammy-20240101", "ubuntu", "jammy", true},
		{"pkg:docker/library%2Fubuntu@24.04", "ubuntu", "24.04", true},
		{"pkg:oci/gcr.io%2Fdistroless%2Fstatic-debian11@latest", "debian", "11", true},
		{"pkg:oci/gcr.io/distroless/base-debian12@nonroot", "debian", "12", true},
		{"pkg:docker/library%2Fnode@20-alpine3.18", "alpine", "3.18", true},
		{"pkg:docker/library%2Fpython@3.12-slim-bookworm", "debian", "bookworm", true},
		{"pkg:docker/library%2Falpine@latest", "", "", false},
		{"pkg:docker/library%2Fdebian@stable-slim", "", "", false},
		{"pkg:docker/temporalio%2Fserver@1.29.1", "", "", false},
		// A segment that is not a known codename is not a release.
		{"pkg:docker/acme%2Fapp@1.0-noble2", "", "", false},
		{"pkg:apk/alpine/musl@1.2.4-r2?distro=3.18.12", "", "", false},
	}
	for _, tt := range tests {
		got, ok := ds.FromImageRef(tt.purl)
		if ok != tt.ok || got.Distribution != tt.distribution || got.Release != tt.release {
			t.Errorf("FromImageRef(%q) = %+v, %v; want %s %s, %v", tt.purl, got, ok, tt.distribution, tt.release, tt.ok)
		}
		if ok && got.Origin != OriginImageRef {
			t.Errorf("FromImageRef(%q).Origin = %q", tt.purl, got.Origin)
		}
	}
}

func TestStatus(t *testing.T) {
	ds := dataset(t)
	tests := []struct {
		name           string
		id             Identity
		status         vulnerabilityv1.DistroStatus
		release, eol   string
		daysPast       int32
		oldest, latest string
	}{
		{
			name: "alpine 3.18 past eol", id: Identity{"alpine", "3.18", "3.18.12", OriginOSPackage},
			status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_EOL, release: "3.18", eol: "2025-05-09", daysPast: 538,
			oldest: "3.21", latest: "3.24",
		},
		{
			name: "debian codename resolves to cycle", id: Identity{"debian", "bookworm", "bookworm", OriginOSPackage},
			status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_SUPPORTED, release: "12", eol: "2028-06-30", daysPast: -610,
			oldest: "12", latest: "13",
		},
		{
			// Debian 11 left LTS on 2026-08-31.
			name: "debian 11 past lts", id: Identity{"debian", "11", "11", OriginOSPackage},
			status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_EOL, release: "11", eol: "2026-08-31", daysPast: 59,
			oldest: "12", latest: "13",
		},
		{
			// An LTS release is pointed at LTS releases only.
			name: "ubuntu lts", id: Identity{"ubuntu", "noble", "noble", OriginOSPackage},
			status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_SUPPORTED, release: "24.04", eol: "2029-05-31",
			daysPast: -945, oldest: "22.04", latest: "26.04",
		},
		{
			name: "alpine edge is unknown", id: Identity{"alpine", "edge", "3.25.0_alpha20260101", OriginOSPackage},
			status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_UNKNOWN, release: "edge",
		},
		{
			name: "untracked distribution is unknown", id: Identity{"fedora", "40", "40", OriginOSPackage},
			status: vulnerabilityv1.DistroStatus_DISTRO_STATUS_UNKNOWN, release: "40",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ds.Status(tt.id, "", scanDate)
			if got.GetStatus() != tt.status {
				t.Errorf("status = %v, want %v", got.GetStatus(), tt.status)
			}
			if got.GetRelease() != tt.release {
				t.Errorf("release = %q, want %q", got.GetRelease(), tt.release)
			}
			if got.GetDatasetSnapshot() != "2026-10-29" {
				t.Errorf("dataset_snapshot = %q", got.GetDatasetSnapshot())
			}
			if tt.eol == "" {
				if got.GetEol() != nil || got.GetDaysPastEol() != 0 {
					t.Errorf("unknown status carries eol %v / days %d", got.GetEol(), got.GetDaysPastEol())
				}
				return
			}
			if e := got.GetEol().AsTime().Format(time.DateOnly); e != tt.eol {
				t.Errorf("eol = %s, want %s", e, tt.eol)
			}
			if got.GetDaysPastEol() != tt.daysPast {
				t.Errorf("days_past_eol = %d, want %d", got.GetDaysPastEol(), tt.daysPast)
			}
			if got.GetOldestSupportedRelease() != tt.oldest || got.GetLatestRelease() != tt.latest {
				t.Errorf("supported = %s..%s, want %s..%s", got.GetOldestSupportedRelease(), got.GetLatestRelease(), tt.oldest, tt.latest)
			}
		})
	}
}

func TestStatusOnEOLDayIsEOL(t *testing.T) {
	ds := dataset(t)
	eolDay := time.Date(2025, 5, 9, 0, 0, 0, 0, time.UTC)
	id := Identity{"alpine", "3.18", "3.18.12", OriginOSPackage}
	if got := ds.Status(id, "", eolDay.Add(-time.Second)).GetStatus(); got != vulnerabilityv1.DistroStatus_DISTRO_STATUS_SUPPORTED {
		t.Errorf("the second before eol: %v, want SUPPORTED", got)
	}
	if got := ds.Status(id, "", eolDay).GetStatus(); got != vulnerabilityv1.DistroStatus_DISTRO_STATUS_EOL {
		t.Errorf("eol day: %v, want EOL", got)
	}
}
