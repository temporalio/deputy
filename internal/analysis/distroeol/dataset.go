package distroeol

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

//go:embed data/releases.json
var releasesJSON []byte

// Release is one release cycle of a distribution.
type Release struct {
	// Distribution is the os-release ID, e.g. "alpine".
	Distribution string
	// Name is the release cycle, e.g. "3.18", "12", "24.04".
	Name string
	// Codename is the lowercased first word of the codename, e.g. "bookworm",
	// "noble". Empty for distributions without codenames.
	Codename string
	// Released is the release date.
	Released time.Time
	// EOL is the first day without free security fixes.
	EOL time.Time
	// ExtendedSupport is the end of paid or extended support, when recorded.
	ExtendedSupport time.Time
	// LTS reports whether the release is a long-term-support release.
	LTS bool
	// Latest is the newest point release, e.g. "3.18.12".
	Latest string
}

// SupportedOn reports whether the release still receives security fixes at t.
func (r Release) SupportedOn(t time.Time) bool {
	return !r.Released.After(t) && t.Before(r.EOL)
}

// Dataset is a dated end-of-life snapshot.
type Dataset struct {
	// Snapshot is the capture date, YYYY-MM-DD.
	Snapshot string
	// Source is where the snapshot was taken from.
	Source string

	releases map[string][]Release // by distribution, newest release first
}

type rawDataset struct {
	Source        string                  `json:"source"`
	Snapshot      string                  `json:"snapshot"`
	Distributions map[string][]rawRelease `json:"distributions"`
}

type rawRelease struct {
	Release         string `json:"release"`
	Codename        string `json:"codename"`
	Released        string `json:"released"`
	EOL             string `json:"eol"`
	ExtendedSupport string `json:"extended_support"`
	LTS             bool   `json:"lts"`
	Latest          string `json:"latest"`
}

// Parse decodes a dataset in the vendored format. Releases without an EOL date
// are dropped: without one there is no verdict to give.
func Parse(data []byte) (*Dataset, error) {
	var raw rawDataset
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode eol dataset: %w", err)
	}
	if _, err := time.Parse(time.DateOnly, raw.Snapshot); err != nil {
		return nil, fmt.Errorf("eol dataset snapshot %q: %w", raw.Snapshot, err)
	}
	ds := &Dataset{Snapshot: raw.Snapshot, Source: raw.Source, releases: map[string][]Release{}}
	for distro, rows := range raw.Distributions {
		for _, row := range rows {
			eol, err := time.Parse(time.DateOnly, row.EOL)
			if err != nil {
				continue
			}
			released, err := time.Parse(time.DateOnly, row.Released)
			if err != nil {
				return nil, fmt.Errorf("eol dataset %s %s: release date %q: %w", distro, row.Release, row.Released, err)
			}
			rel := Release{
				Distribution: distro,
				Name:         row.Release,
				Codename:     row.Codename,
				Released:     released,
				EOL:          eol,
				LTS:          row.LTS,
				Latest:       row.Latest,
			}
			if ext, err := time.Parse(time.DateOnly, row.ExtendedSupport); err == nil {
				rel.ExtendedSupport = ext
			}
			ds.releases[distro] = append(ds.releases[distro], rel)
		}
		slices.SortFunc(ds.releases[distro], func(a, b Release) int { return b.Released.Compare(a.Released) })
	}
	return ds, nil
}

// Default returns the vendored dataset, parsed once.
var Default = sync.OnceValues(func() (*Dataset, error) { return Parse(releasesJSON) })

// Knows reports whether the dataset tracks the distribution at all.
func (d *Dataset) Knows(distribution string) bool {
	return len(d.releases[distribution]) > 0
}

// Lookup finds a release by cycle name or codename.
func (d *Dataset) Lookup(distribution, release string) (Release, bool) {
	release = strings.ToLower(strings.TrimSpace(release))
	if release == "" {
		return Release{}, false
	}
	for _, r := range d.releases[distribution] {
		if r.Name == release || (r.Codename != "" && r.Codename == release) {
			return r, true
		}
	}
	return Release{}, false
}

// Supported returns the oldest and newest releases of the distribution that are
// supported at t. When lts is set only LTS releases are considered, so an LTS
// release is never told to move to a short-lived interim one.
func (d *Dataset) Supported(distribution string, t time.Time, lts bool) (oldest, latest Release, ok bool) {
	for _, r := range d.releases[distribution] { // newest first
		if !r.SupportedOn(t) || (lts && !r.LTS) {
			continue
		}
		if !ok {
			latest, ok = r, true
		}
		oldest = r
	}
	return oldest, latest, ok
}
