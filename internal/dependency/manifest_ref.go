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

const componentKeyGroupPrefix = "deputy:component-key="

// NewManifestRef constructs a ManifestRef and attaches Deputy's internal
// component key metadata without extending the public proto schema.
func NewManifestRef(path, manager string, groups []string, componentKey string) dependencyv1.ManifestRef {
	ref := dependencyv1.ManifestRef{
		Path:    path,
		Manager: manager,
		Groups:  slices.Clone(groups),
	}
	SetManifestRefComponentKey(&ref, componentKey)
	return ref
}

// ManifestRefComponentKey returns Deputy's internal component key metadata for
// source-aware remediation. It is stored in Groups so generated protos do not
// need to change for internal-only routing state.
func ManifestRefComponentKey(ref *dependencyv1.ManifestRef) string {
	if ref == nil {
		return ""
	}
	for _, group := range ref.Groups {
		if key, ok := strings.CutPrefix(group, componentKeyGroupPrefix); ok {
			return key
		}
	}
	return ""
}

// SetManifestRefComponentKey stores internal component key metadata on ref.
func SetManifestRefComponentKey(ref *dependencyv1.ManifestRef, componentKey string) {
	if ref == nil {
		return
	}
	ref.Groups = stripComponentKeyGroup(ref.Groups)
	componentKey = strings.TrimSpace(componentKey)
	if componentKey != "" {
		ref.Groups = append(ref.Groups, componentKeyGroupPrefix+componentKey)
	}
}

// ManifestRefGroups returns dependency groups without Deputy's internal
// component key metadata.
func ManifestRefGroups(ref *dependencyv1.ManifestRef) []string {
	if ref == nil {
		return nil
	}
	return stripComponentKeyGroup(ref.Groups)
}

func stripComponentKeyGroup(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}
	out := make([]string, 0, len(groups))
	for _, group := range groups {
		if strings.HasPrefix(group, componentKeyGroupPrefix) {
			continue
		}
		out = append(out, group)
	}
	return out
}

// MergeManifestRef adds a manifest reference to the list, merging groups if it already exists.
func MergeManifestRef(existing []dependencyv1.ManifestRef, ref *dependencyv1.ManifestRef) []dependencyv1.ManifestRef {
	if ref == nil || ref.Path == "" || ref.Manager == "" {
		return existing
	}
	componentKey := ManifestRefComponentKey(ref)
	for i := range existing {
		cur := &existing[i]
		if cur.Manager == ref.Manager && cur.Path == ref.Path {
			existingComponentKey := ManifestRefComponentKey(cur)
			merged := mergeGroups(ManifestRefGroups(cur), ManifestRefGroups(ref))
			existing[i].Groups = merged
			if existingComponentKey != "" {
				SetManifestRefComponentKey(&existing[i], existingComponentKey)
			} else {
				SetManifestRefComponentKey(&existing[i], componentKey)
			}
			return existing
		}
	}
	existing = append(existing, dependencyv1.ManifestRef{})
	dst := &existing[len(existing)-1]
	dst.Path = ref.Path
	dst.Manager = ref.Manager
	dst.Groups = mergeGroups(nil, ManifestRefGroups(ref))
	SetManifestRefComponentKey(dst, componentKey)
	return existing
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
		}
		if cur.componentKey == "" {
			cur.componentKey = ManifestRefComponentKey(ref)
		}
		cur.groups = mergeGroups(cur.groups, ManifestRefGroups(ref))
		merged[key] = cur
	}
	out := make([]dependencyv1.ManifestRef, 0, len(merged))
	for _, ref := range merged {
		out = append(out, dependencyv1.ManifestRef{})
		dst := &out[len(out)-1]
		dst.Manager = ref.manager
		dst.Path = ref.path
		dst.Groups = sortedUniqueStrings(ref.groups)
		SetManifestRefComponentKey(dst, ref.componentKey)
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
