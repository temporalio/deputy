package osv

import "strings"

// osFamilyOSVNames maps lowercase OS-package ecosystem family aliases to the
// exact ecosystem names OSV's querybatch API accepts. OSV qualifies many OS
// records with a release suffix ("Alpine:v3.19", "Debian:12"); queries pass
// the raw release-qualified string through untouched, so this map only decides
// whether a family is queryable at all. Names not present here (for example
// CentOS or Amazon Linux) are not OSV ecosystems and must not reach
// querybatch, which rejects an entire batch over one unknown ecosystem.
var osFamilyOSVNames = map[string]string{
	"alpine":      "Alpine",
	"debian":      "Debian",
	"ubuntu":      "Ubuntu",
	"almalinux":   "AlmaLinux",
	"rocky":       "Rocky Linux",
	"rocky linux": "Rocky Linux",
	"mageia":      "Mageia",
	"opensuse":    "openSUSE",
	"suse":        "SUSE",
	"sles":        "SUSE",
	"photon":      "Photon OS",
	"photon os":   "Photon OS",
	"red hat":     "Red Hat",
	"redhat":      "Red Hat",
	"rhel":        "Red Hat",
	"chainguard":  "Chainguard",
	"wolfi":       "Wolfi",
	"openeuler":   "openEuler",
	"minimos":     "MinimOS",
}

// OSFamilyOSVName resolves an OS-package ecosystem string, with or without a
// release suffix ("Alpine:v3.19", "debian", "Red Hat"), to its canonical OSV
// ecosystem name. ok is false for anything that is not an OSV-covered OS
// family, including other package ecosystems and OS names OSV does not index.
func OSFamilyOSVName(eco string) (string, bool) {
	fam := strings.TrimSpace(eco)
	if idx := strings.Index(fam, ":"); idx != -1 {
		fam = fam[:idx]
	}
	name, ok := osFamilyOSVNames[strings.ToLower(strings.TrimSpace(fam))]
	return name, ok
}

// OSFamilies returns the canonical OSV names of the OS-package ecosystem
// families OSV covers, deduplicated, for advisory-source coverage declaration.
func OSFamilies() []string {
	seen := make(map[string]bool, len(osFamilyOSVNames))
	out := make([]string, 0, len(osFamilyOSVNames))
	for _, name := range osFamilyOSVNames {
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}
