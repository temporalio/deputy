package scanning

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/analysis/distroeol"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// AdvisoryEOLPrefix starts the advisory ID of an end-of-life finding. The full
// ID names the release, e.g. DEPUTY-EOL-ALPINE-3.18, so a .deputyignore.yaml
// rule accepts one release and does not silently cover the next one to expire.
const AdvisoryEOLPrefix = "DEPUTY-EOL-"

// SourceEOL is the provenance recorded on end-of-life findings.
const SourceEOL = "deputy-eol"

// eolAdvisoryID returns the advisory ID for a release.
func eolAdvisoryID(distribution, release string) string {
	return AdvisoryEOLPrefix + strings.ToUpper(distribution) + "-" + release
}

// distroDisplayNames are the names used in advisory text.
var distroDisplayNames = map[string]string{
	"alpine": "Alpine Linux",
	"debian": "Debian",
	"ubuntu": "Ubuntu",
}

// distroEcosystems are the OSV ecosystem spellings for a release, matching how
// the inventory labels the release's OS packages.
var distroEcosystems = map[string]func(release string) string{
	"alpine": func(r string) string { return "Alpine:v" + r },
	"debian": func(r string) string { return "Debian:" + r },
	"ubuntu": func(r string) string { return "Ubuntu:" + r },
}

// eolCheck is the result of checking an inventory's operating system releases.
type eolCheck struct {
	findings   []vulnerability.Finding
	advisories map[string]*vulnerabilityv1.Advisory
	distros    []*vulnerabilityv1.DistroRelease
	warnings   []string
}

// checkEOL identifies the operating system releases an inventory describes and
// reports each one past its end of life as a finding of kind EOL. It reads the
// release from installed OS package metadata (one record per release, however
// many packages carry it) and from container image references whose tag names
// a release (one record per reference). Every identified release, supported
// or not, is recorded for coverage; a release the dataset does not know is
// recorded as unknown and produces no finding.
//
// The check is offline: it uses the vendored dataset and the scan time.
func checkEOL(pkgs []*dependencyv1.Package, now time.Time, ds *distroeol.Dataset) eolCheck {
	var out eolCheck
	type osKey struct{ distribution, release string }
	osSeen := map[osKey]*vulnerabilityv1.DistroRelease{}

	for _, p := range pkgs {
		if p == nil {
			continue
		}
		if id, ok := distroeol.FromOSPackage(p.GetPurl()); ok {
			k := osKey{id.Distribution, id.Release}
			if prev, ok := osSeen[k]; ok {
				// Keep the most specific version recorded across packages.
				if len(id.Version) > len(prev.GetVersion()) {
					prev.Version = id.Version
				}
				continue
			}
			st := ds.Status(id, "", now)
			osSeen[k] = st
			out.distros = append(out.distros, st)
			continue
		}
		if id, ok := ds.FromImageRef(p.GetPurl()); ok {
			st := ds.Status(id, p.GetName()+":"+p.GetVersion(), now)
			out.distros = append(out.distros, st)
			if st.GetStatus() == vulnerabilityv1.DistroStatus_DISTRO_STATUS_EOL {
				out.addFinding(st, dependency.ID{Name: p.GetName(), Ecosystem: p.GetEcosystem(), PURL: p.GetPurl()}, p.GetVersion(), p.GetDirect(), p.GetLocations())
			}
		}
	}

	// OS package findings are added after the walk so each carries the most
	// specific version seen.
	for _, st := range out.distros {
		if st.GetOrigin() != distroeol.OriginOSPackage || st.GetStatus() != vulnerabilityv1.DistroStatus_DISTRO_STATUS_EOL {
			continue
		}
		eco := st.GetDistribution()
		if f := distroEcosystems[st.GetDistribution()]; f != nil {
			eco = f(st.GetRelease())
		}
		out.addFinding(st, dependency.ID{
			Name:      st.GetDistribution(),
			Ecosystem: eco,
			PURL:      "pkg:generic/" + st.GetDistribution() + "@" + st.GetVersion(),
		}, st.GetVersion(), false, nil)
	}

	for _, st := range out.distros {
		if st.GetStatus() == vulnerabilityv1.DistroStatus_DISTRO_STATUS_UNKNOWN && st.GetOrigin() == distroeol.OriginOSPackage {
			out.warnings = append(out.warnings, fmt.Sprintf(
				"end-of-life status unknown for %s %s: not in the end-of-life dataset (snapshot %s)",
				st.GetDistribution(), st.GetVersion(), ds.Snapshot))
		}
	}
	return out
}

func (c *eolCheck) addFinding(st *vulnerabilityv1.DistroRelease, dep dependency.ID, version string, direct bool, locations []string) {
	id := eolAdvisoryID(st.GetDistribution(), st.GetRelease())
	c.findings = append(c.findings, vulnerability.Finding{
		AdvisoryID: id,
		Dependency: dep,
		Version:    version,
		Direct:     direct,
		Locations:  slices.Clone(locations),
		Affected:   true,
		Sources:    []string{SourceEOL},
	})
	if c.advisories == nil {
		c.advisories = map[string]*vulnerabilityv1.Advisory{}
	}
	if _, ok := c.advisories[id]; !ok {
		c.advisories[id] = eolAdvisory(id, st)
	}
}

// eolAdvisory describes one end-of-life release. The advisory's published
// date is the end-of-life date, the day the exposure began.
func eolAdvisory(id string, st *vulnerabilityv1.DistroRelease) *vulnerabilityv1.Advisory {
	name := cmp.Or(distroDisplayNames[st.GetDistribution()], st.GetDistribution())
	eol := st.GetEol().AsTime().Format(time.DateOnly)
	upgrade := "a supported release"
	if st.GetOldestSupportedRelease() != "" {
		upgrade = fmt.Sprintf("%s %s or later (newest: %s)", name, st.GetOldestSupportedRelease(), st.GetLatestRelease())
	}
	details := fmt.Sprintf(
		"%s %s reached end of life on %s and no longer receives security fixes. "+
			"Vulnerabilities disclosed after that date are not fixed for it, and its advisory "+
			"feed may stop recording them, so this scan's other findings understate the risk. "+
			"Upgrade the base image to %s. End-of-life data: endoflife.date snapshot %s.",
		name, st.GetRelease(), eol, upgrade, st.GetDatasetSnapshot())
	ds := map[string]string{
		"type":           "eol",
		"distribution":   st.GetDistribution(),
		"release":        st.GetRelease(),
		"eol_date":       eol,
		"days_past_eol":  strconv.Itoa(int(st.GetDaysPastEol())),
		"origin":         st.GetOrigin(),
		"eol_dataset":    "endoflife.date@" + st.GetDatasetSnapshot(),
		"remediation":    "upgrade the base image to " + upgrade,
		"latest_release": st.GetLatestRelease(),
	}
	if st.GetOldestSupportedRelease() != "" {
		ds["oldest_supported_release"] = st.GetOldestSupportedRelease()
	}
	return &vulnerabilityv1.Advisory{
		Id:      id,
		Summary: fmt.Sprintf("%s %s is past end of life (%s)", name, st.GetRelease(), eol),
		Details: details,
		Severity: &vulnerabilityv1.Severity{
			Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
			Type:  vulnerabilityv1.SeverityType_SEVERITY_TYPE_CUSTOM,
			Raw:   "high",
		},
		Published:        st.GetEol(),
		Kind:             vulnerabilityv1.FindingKind_FINDING_KIND_EOL,
		Cwes:             []string{"CWE-1104"},
		DatabaseSpecific: ds,
	}
}
