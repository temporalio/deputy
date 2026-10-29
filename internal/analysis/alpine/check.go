package alpine

import (
	"cmp"
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/osv-scalibr/semantic"
	"github.com/package-url/packageurl-go"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/httputil"
)

// SourceName is the provenance recorded on DistroUpdate entries this package
// produces.
const SourceName = "alpine-apkindex"

// DefaultMirror is the Alpine package mirror the branch indexes are read from.
const DefaultMirror = "https://dl-cdn.alpinelinux.org/alpine"

// defaultRepositories are the branch repositories checked, in order. A package
// present in both keeps the newer build.
var defaultRepositories = []string{"main", "community"}

// fetchTimeout bounds one index download.
const fetchTimeout = 60 * time.Second

// Checker compares installed Alpine packages against their branch indexes.
// The zero value reads DefaultMirror with a default HTTP client.
type Checker struct {
	// Mirror is the base URL of an Alpine mirror (the directory holding the
	// v3.NN and edge branches). Empty uses DefaultMirror.
	Mirror string
	// Client performs the index downloads. Nil uses a default client.
	Client *http.Client
}

// branchKey identifies one index set: a release branch and architecture.
type branchKey struct {
	branch string
	arch   string
}

// installed is one Alpine package as the check needs it.
type installed struct {
	ecosystem string
	name      string
	origin    string
	version   string
}

// Check returns the installed source packages that are behind their branch,
// and one warning per branch index that could not be read (the packages on
// that branch went unchecked, which the caller has to be able to say).
// Packages that are not Alpine apk packages, or that do not record the
// release and architecture they were installed from, are ignored. Output is
// sorted for deterministic reports.
func (c *Checker) Check(ctx context.Context, pkgs []*dependencyv1.Package) ([]*vulnerabilityv1.DistroUpdate, []string) {
	byBranch := map[branchKey][]installed{}
	for _, p := range pkgs {
		key, pkg, ok := classify(p)
		if !ok {
			continue
		}
		byBranch[key] = append(byBranch[key], pkg)
	}
	keys := make([]branchKey, 0, len(byBranch))
	for k := range byBranch {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b branchKey) int {
		return cmp.Or(strings.Compare(a.branch, b.branch), strings.Compare(a.arch, b.arch))
	})

	var (
		updates  []*vulnerabilityv1.DistroUpdate
		warnings []string
	)
	for _, key := range keys {
		latest, failed := c.branchIndex(ctx, key)
		for _, repo := range failed {
			warnings = append(warnings, fmt.Sprintf("%s: could not read %s/%s/%s/APKINDEX.tar.gz (%v); Alpine packages from it were not compared against their branch",
				SourceName, key.branch, repo.name, key.arch, repo.err))
		}
		updates = append(updates, compare(byBranch[key], latest, key.branch)...)
	}
	slices.SortFunc(updates, func(a, b *vulnerabilityv1.DistroUpdate) int {
		return cmp.Or(strings.Compare(a.GetEcosystem(), b.GetEcosystem()), strings.Compare(a.GetSourcePackage(), b.GetSourcePackage()), strings.Compare(a.GetInstalledVersion(), b.GetInstalledVersion()))
	})
	return updates, warnings
}

// classify extracts the branch, architecture, and source package of an Alpine
// apk package from its PURL qualifiers, as the inventory writes them
// (pkg:apk/alpine/libssl3@3.5.8-r0?arch=x86_64&distro=3.24.1&origin=openssl).
func classify(p *dependencyv1.Package) (branchKey, installed, bool) {
	pu, err := packageurl.FromString(p.GetPurl())
	if err != nil || !strings.EqualFold(pu.Type, "apk") || !strings.EqualFold(pu.Namespace, "alpine") {
		return branchKey{}, installed{}, false
	}
	q := pu.Qualifiers.Map()
	branch := branchFromDistro(q["distro"])
	version := cmp.Or(p.GetVersion(), pu.Version)
	if branch == "" || q["arch"] == "" || version == "" {
		return branchKey{}, installed{}, false
	}
	return branchKey{branch: branch, arch: q["arch"]}, installed{
		ecosystem: p.GetEcosystem(),
		name:      pu.Name,
		origin:    cmp.Or(q["origin"], pu.Name),
		version:   version,
	}, true
}

// branchFromDistro maps an os-release VERSION_ID to its branch directory:
// "3.24.1" is v3.24, and a development snapshot ("3.25.0_alpha20260101") is
// edge, which is where those snapshots install from.
func branchFromDistro(distro string) string {
	distro = strings.TrimSpace(distro)
	if distro == "" {
		return ""
	}
	if strings.Contains(distro, "_") {
		return "edge"
	}
	parts := strings.Split(distro, ".")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return "v" + parts[0] + "." + parts[1]
}

// available is the newest build of one binary package across the branch's
// repositories.
type available struct {
	version string
	repo    string
}

// repoFailure is a repository index that could not be read.
type repoFailure struct {
	name string
	err  error
}

// branchIndex downloads every repository index for the branch and returns the
// newest build of each binary package, plus the repositories that failed.
func (c *Checker) branchIndex(ctx context.Context, key branchKey) (map[string]available, []repoFailure) {
	latest := map[string]available{}
	var failed []repoFailure
	for _, repo := range defaultRepositories {
		entries, err := c.fetch(ctx, key, repo)
		if err != nil {
			failed = append(failed, repoFailure{name: repo, err: err})
			continue
		}
		for _, e := range entries {
			cur, ok := latest[e.Name]
			if !ok || newer(e.Version, cur.version) {
				latest[e.Name] = available{version: e.Version, repo: key.branch + "/" + repo}
			}
		}
	}
	return latest, failed
}

func (c *Checker) fetch(ctx context.Context, key branchKey, repo string) ([]indexEntry, error) {
	mirror := strings.TrimRight(cmp.Or(c.Mirror, DefaultMirror), "/")
	url := fmt.Sprintf("%s/%s/%s/%s/APKINDEX.tar.gz", mirror, key.branch, repo, key.arch)

	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := c.Client
	if client == nil {
		client = httputil.NewClient(fetchTimeout)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseAPKINDEX(resp.Body)
}

// compare groups the branch's installed packages by source package and
// reports each source whose installed build is older than the newest build of
// any of its binaries. Binaries the branch does not publish (locally built,
// or from a repository not checked) are skipped: absence says nothing about
// the build being current.
func compare(pkgs []installed, latest map[string]available, branch string) []*vulnerabilityv1.DistroUpdate {
	type sourceKey struct {
		ecosystem string
		origin    string
		version   string
	}
	bySource := map[sourceKey]*vulnerabilityv1.DistroUpdate{}
	var order []sourceKey
	for _, p := range pkgs {
		avail, ok := latest[p.name]
		if !ok || !newer(avail.version, p.version) {
			continue
		}
		k := sourceKey{ecosystem: p.ecosystem, origin: p.origin, version: p.version}
		u, ok := bySource[k]
		if !ok {
			u = &vulnerabilityv1.DistroUpdate{
				Ecosystem:        p.ecosystem,
				SourcePackage:    p.origin,
				InstalledVersion: p.version,
				Source:           SourceName,
			}
			bySource[k] = u
			order = append(order, k)
		}
		if !slices.Contains(u.Packages, p.name) {
			u.Packages = append(u.Packages, p.name)
		}
		if u.AvailableVersion == "" || newer(avail.version, u.AvailableVersion) {
			u.AvailableVersion = avail.version
			u.Repository = avail.repo
		}
	}
	out := make([]*vulnerabilityv1.DistroUpdate, 0, len(order))
	for _, k := range order {
		u := bySource[k]
		slices.Sort(u.Packages)
		out = append(out, u)
	}
	return out
}

// newer reports whether version a is strictly newer than b under Alpine
// version ordering. An unparseable version never counts as newer, so bad
// index data cannot manufacture an update.
func newer(a, b string) bool {
	va, err := semantic.Parse(a, "Alpine")
	if err != nil {
		return false
	}
	c, err := va.CompareStr(b)
	return err == nil && c > 0
}
