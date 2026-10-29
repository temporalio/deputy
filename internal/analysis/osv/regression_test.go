package osv

import (
	"slices"
	"strings"
	"testing"

	packageurl "github.com/package-url/packageurl-go"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	"github.com/temporalio/deputy/internal/regression"
)

func loadImage(t *testing.T, name string) *regression.Image {
	t.Helper()
	img, err := regression.Load(name)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func pkgInput(p *dependencyv1.Package) PkgInput {
	return PkgInput{QueryKey: QueryKey{Name: p.GetName(), Version: p.GetVersion(), Ecosystem: p.GetEcosystem(), PURL: p.GetPurl()}}
}

// TestRegressionOSSourceNames checks the binary-to-source mapping against real
// inventories, including the split packages a container actually installs.
// Every OS package that records a source (apk origin, deb source) is queried
// under it; the named pairs pin the cases that motivated the mapping.
func TestRegressionOSSourceNames(t *testing.T) {
	tests := []struct {
		image string
		want  map[string]string // binary package -> OSV query name
	}{
		{"alpine-3.24.0", map[string]string{"libssl3": "openssl", "libcrypto3": "openssl", "busybox-binsh": "busybox"}},
		{"debian-12-slim", map[string]string{"bsdutils": "util-linux", "gpgv": "gnupg2", "libc6": "glibc"}},
		// Ubuntu shares the deb PURL type, and its inventory records source
		// the same way Debian's does.
		{"ubuntu-24.04", map[string]string{"bsdutils": "util-linux", "libapt-pkg6.0t64": "apt", "libc6": "glibc"}},
		// Distroless keeps its package database in /var/lib/dpkg/status.d.
		{"distroless-base-debian12", map[string]string{"libssl3": "openssl", "libc6": "glibc"}},
	}
	for _, tt := range tests {
		t.Run(tt.image, func(t *testing.T) {
			img := loadImage(t, tt.image)
			seen := map[string]bool{}
			withSource := 0
			for _, p := range img.Packages {
				in := pkgInput(p)
				pu, err := packageurl.FromString(p.GetPurl())
				if err != nil {
					t.Fatalf("%s: %v", p.GetPurl(), err)
				}
				q := pu.Qualifiers.Map()
				src := q["origin"]
				if pu.Type == "deb" {
					src = q["source"]
				}
				if src != "" {
					withSource++
					if got := osvQueryName(in); got != src {
						t.Errorf("%s queried as %q, want source %q", p.GetName(), got, src)
					}
				}
				if want, ok := tt.want[p.GetName()]; ok {
					seen[p.GetName()] = true
					if got := osvQueryName(in); got != want {
						t.Errorf("%s queried as %q, want %q", p.GetName(), got, want)
					}
				}
			}
			for name := range tt.want {
				if !seen[name] {
					t.Errorf("%s not in the recorded inventory", name)
				}
			}
			if withSource == 0 {
				t.Error("no package records a source; the inventory shape changed")
			}
		})
	}
}

// TestRegressionDistrolessEcosystem pins that distroless images inventory as
// Debian packages of the release the image name carries.
func TestRegressionDistrolessEcosystem(t *testing.T) {
	for _, name := range []string{"distroless-static-debian12", "distroless-base-debian12"} {
		img := loadImage(t, name)
		if len(img.Packages) == 0 {
			t.Fatalf("%s: empty inventory", name)
		}
		for _, p := range img.Packages {
			if p.GetEcosystem() != "Debian:12" || !strings.HasPrefix(p.GetPurl(), "pkg:deb/debian/") {
				t.Errorf("%s: %s is %q", name, p.GetPurl(), p.GetEcosystem())
			}
			if !slices.ContainsFunc(p.GetLocations(), func(l string) bool { return strings.HasPrefix(l, "var/lib/dpkg/status.d/") }) {
				t.Errorf("%s: %s not read from status.d: %v", name, p.GetPurl(), p.GetLocations())
			}
		}
	}
}

// serverModule is the module whose advisories the regression images exercise.
const serverModule = "go.temporal.io/server"

// TestRegressionGoBinariesQueriedPerBinary uses an image that bundles several
// Go binaries, each built against its own version of the same module. Every
// binary's build info is a separate inventory entry and is matched at its own
// version, rather than collapsed onto one go.mod.
func TestRegressionGoBinariesQueriedPerBinary(t *testing.T) {
	img := loadImage(t, "admin-tools-1.31.4")
	binaries := map[string]bool{}
	versions := map[string][]string{} // server version -> binaries
	for _, p := range img.Packages {
		if p.GetEcosystem() != "Go" {
			continue
		}
		for _, l := range p.GetLocations() {
			binaries[l] = true
		}
		if p.GetName() == serverModule {
			versions[p.GetVersion()] = append(versions[p.GetVersion()], p.GetLocations()...)
		}
	}
	if len(binaries) < 5 {
		t.Fatalf("Go binaries = %d, want at least 5: %v", len(binaries), binaries)
	}
	if len(versions) < 2 {
		t.Fatalf("server module versions = %v, want each binary's own build", versions)
	}
	// None of these builds is in an advisory range, including the
	// pseudo-versions on the release branch above the last fix.
	for v, locs := range versions {
		resetDiskCache(t)
		vulns, _, err := QueryRaw(t.Context(), overMatchingServerAdvisoryClient{}, []PkgInput{{
			QueryKey:       QueryKey{Name: serverModule, Version: v, Ecosystem: "Go"},
			PackageContext: PackageContext{Locations: locs},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if len(vulns) != 0 {
			t.Errorf("%s@%s (%v) reported against a fixed range", serverModule, v, locs)
		}
	}
}

// TestRegressionOldServerReleaseTruePositive uses a real old release: the
// bundled CLI binaries link the server module at pre-1.20 pseudo-versions,
// inside the advisory's open-from-zero range, and are reported.
//
// It also records, without endorsing, how the server binary itself is matched.
// That binary was built from a checkout without a tag, so its build info
// records the main module as "(devel)". An unversioned main module is reported
// against every advisory whose range opens at zero, the same as v0.0.0.
// Whether to keep, drop, or resolve such versions (for example from the
// image's version label) is an open decision; this test changes when it is
// made.
func TestRegressionOldServerReleaseTruePositive(t *testing.T) {
	img := loadImage(t, "server-1.20.0")
	got := map[string]bool{}
	for _, p := range img.Packages {
		if p.GetName() != serverModule {
			continue
		}
		resetDiskCache(t)
		vulns, _, err := QueryRaw(t.Context(), overMatchingServerAdvisoryClient{}, []PkgInput{{
			QueryKey:       QueryKey{Name: serverModule, Version: p.GetVersion(), Ecosystem: "Go"},
			PackageContext: PackageContext{Locations: p.GetLocations()},
		}})
		if err != nil {
			t.Fatal(err)
		}
		got[p.GetVersion()+" "+strings.Join(p.GetLocations(), ",")] = len(vulns) > 0
	}
	want := map[string]bool{
		"1.18.1-0.20230207023301-52c3a9eefb06 usr/local/bin/temporal": true,
		"1.18.1-0.20230217005328-b313b7f58641 usr/local/bin/tctl":     true,
		"(devel) usr/local/bin/temporal-server":                       true, // current behavior, see above
	}
	if len(got) != len(want) {
		t.Fatalf("server module entries = %v, want %v", got, want)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: reported = %v, want %v", k, got[k], w)
		}
	}
}

// TestUnversionedMainModuleCurrentBehavior documents, with synthetic inputs,
// what happens to main-module versions that carry no release: "(devel)" and
// v0.0.0 forms are reported when a range opens at zero, and an empty version
// is not queried. A pseudo-version above the fix is not reported (see
// TestQueryRawMainModuleDevVersionAboveFix). This pins current behavior for an
// open decision; it is not a statement that the behavior is right.
func TestUnversionedMainModuleCurrentBehavior(t *testing.T) {
	tests := []struct {
		version  string
		reported bool
	}{
		{"(devel)", true},
		{"v0.0.0", true},
		{"0.0.0", true},
		{"v0.0.0-20261020120000-abcdefabcdef", true},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			resetDiskCache(t)
			vulns, _, err := QueryRaw(t.Context(), overMatchingServerAdvisoryClient{}, []PkgInput{{
				QueryKey:       QueryKey{Name: serverModule, Version: tt.version, Ecosystem: "Go"},
				PackageContext: PackageContext{IsDirect: true},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if got := len(vulns) > 0; got != tt.reported {
				t.Errorf("reported = %v, want %v", got, tt.reported)
			}
		})
	}
}
