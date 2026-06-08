package dependency

import (
	"cmp"
	"slices"
	"sort"
	"strings"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	"github.com/temporalio/deputy/internal/collections"
)

type manifestRefKey struct {
	manager string
	path    string
}

type manifestRefValue struct {
	manager      string
	path         string
	componentKey string
	groups       []string
}

// NewManifestRef constructs a ManifestRef.
func NewManifestRef(path, manager string, groups []string, componentKey string) dependencyv1.ManifestRef {
	return dependencyv1.ManifestRef{
		Path:         path,
		Manager:      manager,
		Groups:       slices.Clone(groups),
		ComponentKey: strings.TrimSpace(componentKey),
	}
}

// ManifestRefComponentKey returns the dependency's key exactly as written in
// the manifest (e.g. a mise.toml tool key like "npm:lodash" or "go"), or "" when
// unset. It lets source-aware remediation target the right manifest entry even
// when a finding is reported under a remapped name (mise/asdf tools are scanned
// under another ecosystem's coordinate — e.g. a mise "go" runtime is reported as
// "stdlib"/"toolchain"). See the ManifestRef.component_key proto field for the
// full rationale. Nil-safe accessor for [dependencyv1.ManifestRef.ComponentKey].
func ManifestRefComponentKey(ref *dependencyv1.ManifestRef) string {
	return ref.GetComponentKey()
}

// SetManifestRefComponentKey sets ref's manifest-declared component key.
func SetManifestRefComponentKey(ref *dependencyv1.ManifestRef, componentKey string) {
	if ref == nil {
		return
	}
	ref.ComponentKey = strings.TrimSpace(componentKey)
}

// ManifestRefGroups returns ref's dependency groups, or nil. It is a nil-safe
// accessor retained for call-site convenience.
func ManifestRefGroups(ref *dependencyv1.ManifestRef) []string {
	return ref.GetGroups()
}

// MergeManifestRef adds a manifest reference to the list, merging groups if it already exists.
func MergeManifestRef(existing []dependencyv1.ManifestRef, ref *dependencyv1.ManifestRef) []dependencyv1.ManifestRef {
	if ref == nil || ref.Path == "" || ref.Manager == "" {
		return existing
	}
	for i := range existing {
		cur := &existing[i]
		if cur.Manager == ref.Manager && cur.Path == ref.Path {
			cur.Groups = mergeGroups(cur.Groups, ref.Groups)
			if cur.ComponentKey == "" {
				cur.ComponentKey = ref.ComponentKey
			}
			return existing
		}
	}
	return append(existing, dependencyv1.ManifestRef{
		Path:         ref.Path,
		Manager:      ref.Manager,
		Groups:       mergeGroups(nil, ref.Groups),
		ComponentKey: ref.ComponentKey,
	})
}

// SortAndUniqueManifestRefs deduplicates and sorts manifest references.
func SortAndUniqueManifestRefs(refs []dependencyv1.ManifestRef) []dependencyv1.ManifestRef {
	if len(refs) == 0 {
		return refs
	}
	merged := map[manifestRefKey]*manifestRefValue{}
	for i := range refs {
		ref := &refs[i]
		key := manifestRefKey{manager: ref.Manager, path: ref.Path}
		cur, ok := merged[key]
		if !ok {
			cur = &manifestRefValue{manager: ref.Manager, path: ref.Path}
			merged[key] = cur
		}
		if cur.componentKey == "" {
			cur.componentKey = ref.ComponentKey
		}
		cur.groups = mergeGroups(cur.groups, ref.Groups)
	}
	out := make([]dependencyv1.ManifestRef, 0, len(merged))
	for _, ref := range merged {
		out = append(out, dependencyv1.ManifestRef{
			Manager:      ref.manager,
			Path:         ref.path,
			Groups:       sortedUniqueStrings(ref.groups),
			ComponentKey: ref.componentKey,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a := &out[i]
		b := &out[j]
		if c := cmp.Compare(a.Manager, b.Manager); c != 0 {
			return c < 0
		}
		return cmp.Compare(a.Path, b.Path) < 0
	})
	return out
}

// mergeGroups combines two lists of groups, removing duplicates.
func mergeGroups(base []string, extra []string) []string {
	set := collections.NewSet[string]()
	for _, g := range base {
		set.Add(g)
	}
	for _, g := range extra {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if !set.Add(g) {
			continue
		}
		base = append(base, g)
	}
	return base
}

// sortedUniqueStrings returns a sorted list of unique strings.
func sortedUniqueStrings(values []string) []string {
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
