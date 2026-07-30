package osv

import "testing"

// TestOSFamilyOSVName pins the OS-family resolution rules: release suffixes
// strip, casing and aliases normalize, and non-OSV OS names (and package
// ecosystems) do not resolve.
func TestOSFamilyOSVName(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{"Alpine:v3.19", "Alpine", true},
		{"alpine", "Alpine", true},
		{"Debian:12", "Debian", true},
		{"Ubuntu:22.04:LTS", "Ubuntu", true},
		{"rhel", "Red Hat", true},
		{"Rocky Linux:9", "Rocky Linux", true},
		{"wolfi", "Wolfi", true},
		{" chainguard ", "Chainguard", true},
		{"centos", "", false},
		{"amazon linux", "", false},
		{"npm", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, ok := OSFamilyOSVName(tt.in)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("OSFamilyOSVName(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

// TestOSVAPIQueryableOSPackages guards the regression where the queryability
// gate (added so unknown ecosystems like mise cannot abort a whole OSV batch)
// also silenced OS-package ecosystems, dropping every OS-package finding from
// container scans.
func TestOSVAPIQueryableOSPackages(t *testing.T) {
	tests := []struct {
		name string
		in   PkgInput
		want bool
	}{
		{"alpine release-qualified", PkgInput{QueryKey: QueryKey{Name: "musl", Version: "1.2.4", Ecosystem: "Alpine:v3.19"}}, true},
		{"debian release-qualified", PkgInput{QueryKey: QueryKey{Name: "openssl", Version: "3.0.11", Ecosystem: "Debian:12"}}, true},
		{"package ecosystem", PkgInput{QueryKey: QueryKey{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"}}, true},
		{"inventory-only tool manager", PkgInput{QueryKey: QueryKey{Name: "node", Version: "20.0.0", Ecosystem: "mise"}}, false},
		{"os name osv does not index", PkgInput{QueryKey: QueryKey{Name: "bash", Version: "5", Ecosystem: "centos"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := osvAPIQueryable(tt.in); got != tt.want {
				t.Fatalf("osvAPIQueryable(%v) = %v, want %v", tt.in.QueryKey, got, tt.want)
			}
		})
	}
}
