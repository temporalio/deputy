package osv

import (
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestIsVersionAffected_Debian(t *testing.T) {
	tests := []struct {
		name         string
		pkgName      string
		pkgVersion   string
		pkgEcosystem string
		vuln         osvschema.Vulnerability
		want         bool
	}{
		{
			name:         "curl fixed in deb12u4, installed deb12u5 - should NOT be affected",
			pkgName:      "curl",
			pkgVersion:   "7.88.1-10+deb12u5",
			pkgEcosystem: "Debian:12",
			vuln: osvschema.Vulnerability{
				ID: "DEBIAN-CVE-2023-38545",
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Name:      "curl",
							Ecosystem: "Debian:12",
						},
						Ranges: []osvschema.Range{
							{
								Type: osvschema.RangeEcosystem,
								Events: []osvschema.Event{
									{Introduced: "0"},
									{Fixed: "7.88.1-10+deb12u4"},
								},
							},
						},
					},
				},
			},
			want: false, // 7.88.1-10+deb12u5 > 7.88.1-10+deb12u4, so NOT affected
		},
		{
			name:         "curl fixed in deb12u4, installed deb12u3 - should BE affected",
			pkgName:      "curl",
			pkgVersion:   "7.88.1-10+deb12u3",
			pkgEcosystem: "Debian:12",
			vuln: osvschema.Vulnerability{
				ID: "DEBIAN-CVE-2023-38545",
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Name:      "curl",
							Ecosystem: "Debian:12",
						},
						Ranges: []osvschema.Range{
							{
								Type: osvschema.RangeEcosystem,
								Events: []osvschema.Event{
									{Introduced: "0"},
									{Fixed: "7.88.1-10+deb12u4"},
								},
							},
						},
					},
				},
			},
			want: true, // 7.88.1-10+deb12u3 < 7.88.1-10+deb12u4, so affected
		},
		{
			name:         "package not in affected list",
			pkgName:      "other-package",
			pkgVersion:   "1.0.0",
			pkgEcosystem: "Debian:12",
			vuln: osvschema.Vulnerability{
				ID: "DEBIAN-CVE-2023-38545",
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Name:      "curl",
							Ecosystem: "Debian:12",
						},
						Ranges: []osvschema.Range{
							{
								Type: osvschema.RangeEcosystem,
								Events: []osvschema.Event{
									{Introduced: "0"},
									{Fixed: "7.88.1-10+deb12u4"},
								},
							},
						},
					},
				},
			},
			want: false,
		},
		{
			name:         "open-ended range with no fix - should be affected",
			pkgName:      "vulnerable-pkg",
			pkgVersion:   "1.0.0-1",
			pkgEcosystem: "Debian:12",
			vuln: osvschema.Vulnerability{
				ID: "DEBIAN-CVE-2024-XXXX",
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Name:      "vulnerable-pkg",
							Ecosystem: "Debian:12",
						},
						Ranges: []osvschema.Range{
							{
								Type: osvschema.RangeEcosystem,
								Events: []osvschema.Event{
									{Introduced: "0"},
								},
							},
						},
					},
				},
			},
			want: true, // No fixed version, so all versions affected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := PkgInput{QueryKey: QueryKey{
				Name:      tt.pkgName,
				Version:   tt.pkgVersion,
				Ecosystem: tt.pkgEcosystem,
			}}
			got := isVersionAffected(tt.vuln, pkg)
			if got != tt.want {
				t.Errorf("isVersionAffected() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsVersionAffected_Alpine(t *testing.T) {
	tests := []struct {
		name         string
		pkgName      string
		pkgVersion   string
		pkgEcosystem string
		vuln         osvschema.Vulnerability
		want         bool
	}{
		{
			name:         "Alpine package fixed - should NOT be affected",
			pkgName:      "busybox",
			pkgVersion:   "1.36.1-r5",
			pkgEcosystem: "Alpine:3.18",
			vuln: osvschema.Vulnerability{
				ID: "CVE-2023-XXXXX",
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Name:      "busybox",
							Ecosystem: "Alpine:3.18",
						},
						Ranges: []osvschema.Range{
							{
								Type: osvschema.RangeEcosystem,
								Events: []osvschema.Event{
									{Introduced: "0"},
									{Fixed: "1.36.1-r4"},
								},
							},
						},
					},
				},
			},
			want: false, // 1.36.1-r5 > 1.36.1-r4
		},
		{
			name:         "Alpine package vulnerable - should BE affected",
			pkgName:      "busybox",
			pkgVersion:   "1.36.1-r3",
			pkgEcosystem: "Alpine:3.18",
			vuln: osvschema.Vulnerability{
				ID: "CVE-2023-XXXXX",
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Name:      "busybox",
							Ecosystem: "Alpine:3.18",
						},
						Ranges: []osvschema.Range{
							{
								Type: osvschema.RangeEcosystem,
								Events: []osvschema.Event{
									{Introduced: "0"},
									{Fixed: "1.36.1-r4"},
								},
							},
						},
					},
				},
			},
			want: true, // 1.36.1-r3 < 1.36.1-r4
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := PkgInput{QueryKey: QueryKey{
				Name:      tt.pkgName,
				Version:   tt.pkgVersion,
				Ecosystem: tt.pkgEcosystem,
			}}
			got := isVersionAffected(tt.vuln, pkg)
			if got != tt.want {
				t.Errorf("isVersionAffected() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsVersionAffected_Go(t *testing.T) {
	tests := []struct {
		name         string
		pkgName      string
		pkgVersion   string
		pkgEcosystem string
		vuln         osvschema.Vulnerability
		want         bool
	}{
		{
			name:         "Go package vulnerable - in range",
			pkgName:      "github.com/foo/bar",
			pkgVersion:   "v1.2.3",
			pkgEcosystem: "Go",
			vuln: osvschema.Vulnerability{
				ID: "GO-2023-XXXX",
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Name:      "github.com/foo/bar",
							Ecosystem: "Go",
						},
						Ranges: []osvschema.Range{
							{
								Type: osvschema.RangeSemVer,
								Events: []osvschema.Event{
									{Introduced: "1.0.0"},
									{Fixed: "1.3.0"},
								},
							},
						},
					},
				},
			},
			want: true, // v1.2.3 is in [v1.0.0, v1.3.0)
		},
		{
			name:         "Go package fixed - above range",
			pkgName:      "github.com/foo/bar",
			pkgVersion:   "v1.4.0",
			pkgEcosystem: "Go",
			vuln: osvschema.Vulnerability{
				ID: "GO-2023-XXXX",
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Name:      "github.com/foo/bar",
							Ecosystem: "Go",
						},
						Ranges: []osvschema.Range{
							{
								Type: osvschema.RangeSemVer,
								Events: []osvschema.Event{
									{Introduced: "1.0.0"},
									{Fixed: "1.3.0"},
								},
							},
						},
					},
				},
			},
			want: false, // v1.4.0 >= v1.3.0
		},
		{
			name:         "Go pseudo-version affected - introduced 0 with fixed pseudo-version",
			pkgName:      "github.com/gomarkdown/markdown",
			pkgVersion:   "v0.0.0-20240729212818-a2a9c4f76ef5",
			pkgEcosystem: "Go",
			vuln: osvschema.Vulnerability{
				ID: "GHSA-77fj-vx54-gvh7",
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Name:      "github.com/gomarkdown/markdown",
							Ecosystem: "Go",
						},
						Ranges: []osvschema.Range{
							{
								Type: osvschema.RangeSemVer,
								Events: []osvschema.Event{
									{Introduced: "0"},
									{Fixed: "0.0.0-20260411013819-759bbc3e3207"},
								},
							},
						},
					},
				},
			},
			want: true, // pseudo-version is before the fix
		},
		{
			name:         "Go pseudo-version not affected - above fixed pseudo-version",
			pkgName:      "github.com/gomarkdown/markdown",
			pkgVersion:   "v0.0.0-20260501000000-aaaaaaaaaaaa",
			pkgEcosystem: "Go",
			vuln: osvschema.Vulnerability{
				ID: "GHSA-77fj-vx54-gvh7",
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Name:      "github.com/gomarkdown/markdown",
							Ecosystem: "Go",
						},
						Ranges: []osvschema.Range{
							{
								Type: osvschema.RangeSemVer,
								Events: []osvschema.Event{
									{Introduced: "0"},
									{Fixed: "0.0.0-20260411013819-759bbc3e3207"},
								},
							},
						},
					},
				},
			},
			want: false, // pseudo-version is after the fix
		},
		{
			name:         "Go pseudo-version affected - open-ended introduced 0 with no fix",
			pkgName:      "github.com/gomarkdown/markdown",
			pkgVersion:   "v0.0.0-20240729212818-a2a9c4f76ef5",
			pkgEcosystem: "Go",
			vuln: osvschema.Vulnerability{
				ID: "GHSA-TEST-OPEN",
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Name:      "github.com/gomarkdown/markdown",
							Ecosystem: "Go",
						},
						Ranges: []osvschema.Range{
							{
								Type: osvschema.RangeSemVer,
								Events: []osvschema.Event{
									{Introduced: "0"},
								},
							},
						},
					},
				},
			},
			want: true, // all versions affected, no fix available
		},
		{
			name:         "Go pseudo-version not affected - below non-zero introduced",
			pkgName:      "github.com/gomarkdown/markdown",
			pkgVersion:   "v0.0.0-20240729212818-a2a9c4f76ef5",
			pkgEcosystem: "Go",
			vuln: osvschema.Vulnerability{
				ID: "GHSA-TEST-NONZERO",
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{
							Name:      "github.com/gomarkdown/markdown",
							Ecosystem: "Go",
						},
						Ranges: []osvschema.Range{
							{
								Type: osvschema.RangeSemVer,
								Events: []osvschema.Event{
									{Introduced: "0.0.0-20250101000000-bbbbbbbbbbbb"},
									{Fixed: "0.0.0-20260411013819-759bbc3e3207"},
								},
							},
						},
					},
				},
			},
			want: false, // pseudo-version is below introduced
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := PkgInput{QueryKey: QueryKey{
				Name:      tt.pkgName,
				Version:   tt.pkgVersion,
				Ecosystem: tt.pkgEcosystem,
			}}
			got := isVersionAffected(tt.vuln, pkg)
			if got != tt.want {
				t.Errorf("isVersionAffected() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapToSemanticEcosystem(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Debian:12", "Debian"},
		{"Debian:11", "Debian"},
		{"debian", "Debian"},
		{"Ubuntu:22.04", "Ubuntu"},
		{"Alpine:3.18", "Alpine"},
		{"alpine", "Alpine"},
		{"npm", "npm"},
		{"PyPI", "PyPI"},
		{"python", "PyPI"},
		{"Go", "Go"},
		{"golang", "Go"},
		{"Red Hat", "Red Hat"},
		{"unknown-ecosystem", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapToSemanticEcosystem(tt.input)
			if got != tt.want {
				t.Errorf("mapToSemanticEcosystem(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
