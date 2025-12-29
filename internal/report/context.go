package report

import (
	"cmp"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/picatz/deputy/internal/collections"
	"github.com/picatz/deputy/internal/ecosystem"
	"github.com/picatz/deputy/internal/inventory/manifests"
	"github.com/picatz/deputy/internal/vuln"
)

// ManifestEntry represents a single manifest file in the display context.
type ManifestEntry struct {
	Path   string
	Groups []string
}

// ManifestGroup represents a group of manifests managed by a specific package manager.
type ManifestGroup struct {
	Manager string
	Entries []ManifestEntry
}

// ArtifactGroup represents a group of artifacts managed by a specific package manager.
type ArtifactGroup struct {
	Manager string
	Entries []string
}

// ManifestContext holds the organized structure of sources and artifacts for display.
type ManifestContext struct {
	Sources   []ManifestGroup
	Artifacts []ArtifactGroup
}

// BuildManifestContext constructs a ManifestContext from a list of consolidated vulnerabilities.
func BuildManifestContext(list []vuln.ConsolidatedVulnerability) ManifestContext {
	ctx := ManifestContext{}
	if len(list) == 0 {
		return ctx
	}
	manifestPaths := collections.NewSet[string]()
	groupEntries := map[string]map[string]*ManifestEntry{}
	displayGroups := map[string]*ManifestGroup{}
	manifestManagers := map[string]string{}
	dirManagers := map[string]string{}
	for _, v := range list {
		for _, ref := range v.ManifestRefs {
			pathStr := strings.TrimSpace(ref.Path)
			manager := strings.TrimSpace(ref.Manager)
			if pathStr == "" && manager == "" {
				continue
			}
			if pathStr != "" {
				manifestPaths.Add(pathStr)
				manifestManagers[pathStr] = manager
				dir := strings.TrimPrefix(path.Dir(pathStr), "./")
				if dir == "." {
					dir = ""
				}
				if manager != "" {
					dirManagers[dir] = manager
				}
			}
			key := strings.ToLower(manager)
			entries := groupEntries[key]
			if entries == nil {
				entries = map[string]*ManifestEntry{}
				groupEntries[key] = entries
			}
			entry := entries[pathStr]
			if entry == nil {
				entry = &ManifestEntry{Path: pathStr}
				entries[pathStr] = entry
			}
			entry.Groups = mergeGroupNames(entry.Groups, ref.Groups)
			grp := displayGroups[key]
			if grp == nil {
				grp = &ManifestGroup{Manager: manager}
				displayGroups[key] = grp
			}
			if manager != "" {
				grp.Manager = manager
			}
		}
	}

	managerKeys := slices.SortedFunc(maps.Keys(groupEntries), func(a, b string) int {
		ra := ecosystem.ManagerRank(a)
		rb := ecosystem.ManagerRank(b)
		if ra != rb {
			return cmp.Compare(ra, rb)
		}
		return cmp.Compare(a, b)
	})

	for _, key := range managerKeys {
		entries := groupEntries[key]
		grp := displayGroups[key]
		if grp == nil {
			grp = &ManifestGroup{Manager: key}
		}
		entryList := make([]ManifestEntry, 0, len(entries))
		for _, entry := range entries {
			entry.Groups = uniqueSortedStrings(entry.Groups)
			entryList = append(entryList, *entry)
		}
		slices.SortFunc(entryList, func(a, b ManifestEntry) int {
			return cmp.Compare(a.Path, b.Path)
		})
		grp.Entries = entryList
		if grp.Manager == "" && len(entryList) > 0 {
			grp.Manager = key
		}
		ctx.Sources = append(ctx.Sources, *grp)
	}

	artifactGroups := map[string]collections.Set[string]{}
	artifactManagerNames := map[string]string{}
	for _, v := range list {
		for _, loc := range v.Locations {
			loc = strings.TrimSpace(loc)
			if loc == "" {
				continue
			}
			if manifestPaths.Has(loc) {
				continue
			}
			mgr := manifests.InferArtifactManager(loc, manifestManagers, dirManagers)
			key := strings.ToLower(mgr)
			if mgr == "" {
				key = ""
			}
			set := artifactGroups[key]
			if set == nil {
				set = collections.NewSet[string]()
				artifactGroups[key] = set
			}
			if !set.Add(loc) {
				continue
			}
			artifactManagerNames[key] = mgr
		}
	}

	artifactKeys := slices.SortedFunc(maps.Keys(artifactGroups), func(a, b string) int {
		ra := ecosystem.ManagerRank(artifactManagerNames[a])
		rb := ecosystem.ManagerRank(artifactManagerNames[b])
		if ra != rb {
			return cmp.Compare(ra, rb)
		}
		return cmp.Compare(artifactManagerNames[a], artifactManagerNames[b])
	})

	for _, key := range artifactKeys {
		set := artifactGroups[key]
		entries := set.Slice()
		slices.Sort(entries)
		ctx.Artifacts = append(ctx.Artifacts, ArtifactGroup{
			Manager: artifactManagerNames[key],
			Entries: entries,
		})
	}
	return ctx
}

// mergeGroupNames merges two lists of group names, ensuring uniqueness and case-insensitivity.
func mergeGroupNames(base []string, extra []string) []string {
	set := collections.NewSet[string]()
	for _, g := range base {
		set.Add(strings.ToLower(g))
	}
	for _, g := range extra {
		gTrim := strings.TrimSpace(g)
		if gTrim == "" {
			continue
		}
		key := strings.ToLower(gTrim)
		if !set.Add(key) {
			continue
		}
		base = append(base, gTrim)
	}
	return base
}

// uniqueSortedStrings returns a sorted list of unique strings from the input.
func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	set := collections.NewSet[string]()
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !set.Add(v) {
			continue
		}
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}
