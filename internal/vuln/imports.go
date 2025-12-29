package vuln

import (
	"maps"
	"slices"
	"strings"

	"github.com/picatz/deputy/internal/collections"
)

// MergeAffectedImports deduplicates import paths and symbols while keeping output stable.
// Callers can pass multiple slices (e.g., from aliases) and receive a merged, sorted result.
func MergeAffectedImports(importSets ...[]AffectedImport) []AffectedImport {
	pathMap := make(map[string]collections.Set[string])
	for _, imports := range importSets {
		for _, imp := range imports {
			path := strings.TrimSpace(imp.Path)
			if path == "" {
				continue
			}
			if _, ok := pathMap[path]; !ok {
				pathMap[path] = collections.NewSet[string]()
			}
			if len(imp.Symbols) == 0 {
				continue
			}
			for _, sym := range imp.Symbols {
				s := strings.TrimSpace(sym)
				if s == "" {
					continue
				}
				pathMap[path].Add(s)
			}
		}
	}
	if len(pathMap) == 0 {
		return nil
	}
	paths := slices.Sorted(maps.Keys(pathMap))
	out := make([]AffectedImport, 0, len(paths))
	for _, p := range paths {
		symSet := pathMap[p]
		syms := symSet.Slice()
		slices.Sort(syms)
		out = append(out, AffectedImport{Path: p, Symbols: syms})
	}
	return out
}
