package osv

import (
	"strings"

	"github.com/google/osv-scalibr/purl"
	"github.com/package-url/packageurl-go"
)

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

// osSourceQualifiers maps an OS package's PURL type to the qualifier that
// names the source package it was built from. Alpine and Debian (and Ubuntu,
// which shares the deb type) key their OSV records by source package, so a
// binary package split from a larger source (libssl3 and libcrypto3 from
// openssl, busybox-binsh from busybox) only matches when queried under that
// source name. These are the qualifiers the inventory extractors write.
var osSourceQualifiers = map[string]string{
	"apk": purl.Origin,
	"deb": purl.Source,
}

// osSourceName returns the source package name OSV indexes an OS package
// under, or "" when the input is not an OS package or carries no source
// qualifier, in which case the binary name is the only coordinate available.
func osSourceName(p PkgInput) string {
	if _, ok := OSFamilyOSVName(p.Ecosystem); !ok || p.PURL == "" {
		return ""
	}
	pu, err := purl.FromString(p.PURL)
	if err != nil {
		return ""
	}
	key, ok := osSourceQualifiers[strings.ToLower(pu.Type)]
	if !ok {
		return ""
	}
	return strings.TrimSpace(packageurl.Qualifiers(pu.Qualifiers).Map()[key])
}

// osvQueryName returns the package name to send to OSV: the source package
// for OS packages that record one, otherwise the package's own name. The
// finding still reports the installed binary package; only the lookup
// coordinate changes.
func osvQueryName(p PkgInput) string {
	if src := osSourceName(p); src != "" {
		return src
	}
	return p.Name
}
