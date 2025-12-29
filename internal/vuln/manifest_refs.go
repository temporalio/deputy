package vuln

import (
	"cmp"
	"slices"
	"strings"

	"github.com/picatz/deputy/internal/collections"
)

type manifestRefKey struct {
	manager string
	path    string
}

// MergeManifestReference adds a manifest reference to the list, merging groups if it already exists.
func MergeManifestReference(existing []ManifestReference, ref ManifestReference) []ManifestReference {
	if ref.Path == "" || ref.Manager == "" {
		return existing
	}
	for i, cur := range existing {
		if cur.Manager == ref.Manager && cur.Path == ref.Path {
			merged := mergeGroups(cur.Groups, ref.Groups)
			existing[i].Groups = merged
			return existing
		}
	}
	ref.Groups = mergeGroups(nil, ref.Groups)
	return append(existing, ref)
}

// SortAndUniqueManifestRefs deduplicates and sorts manifest references.
func SortAndUniqueManifestRefs(refs []ManifestReference) []ManifestReference {
	if len(refs) == 0 {
		return refs
	}
	merged := map[manifestRefKey]ManifestReference{}
	for _, ref := range refs {
		key := manifestRefKey{manager: ref.Manager, path: ref.Path}
		cur, ok := merged[key]
		if !ok {
			cur = ManifestReference{Manager: ref.Manager, Path: ref.Path}
		}
		cur.Groups = mergeGroups(cur.Groups, ref.Groups)
		merged[key] = cur
	}
	out := make([]ManifestReference, 0, len(merged))
	for _, ref := range merged {
		ref.Groups = sortedUnique(ref.Groups)
		out = append(out, ref)
	}
	slices.SortFunc(out, func(a, b ManifestReference) int {
		if c := cmp.Compare(a.Manager, b.Manager); c != 0 {
			return c
		}
		return cmp.Compare(a.Path, b.Path)
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

// sortedUnique returns a sorted list of unique strings.
func sortedUnique(values []string) []string {
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
