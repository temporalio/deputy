package cmd

import (
	"github.com/google/osv-scalibr/extractor"
	analysis "github.com/picatz/deputy/internal/analysis"
	cmp "github.com/picatz/deputy/internal/compare"
)

// packagesToInputs converts a slice of extractor.Package objects into
// analysis.PkgInput records suitable for OSV queries. It normalizes package
// names, deduplicates modules, and annotates whether each dependency is direct
// according to the provided dependency map.
func packagesToInputs(pkgs []*extractor.Package, deps map[string]bool) []analysis.PkgInput {
	if len(pkgs) == 0 {
		return nil
	}
	if deps == nil {
		deps = map[string]bool{}
	}
	seen := map[string]struct{}{}
	inputs := make([]analysis.PkgInput, 0, len(pkgs))
	for _, p := range pkgs {
		if p == nil || p.Name == "" || p.Version == "" {
			continue
		}
		info := cmp.ParseGoPackage(p)
		key := p.Name + "@" + p.Version
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		root := cmp.GetModuleRoot(info.CanonicalName)
		inputs = append(inputs, analysis.PkgInput{
			Name:     p.Name,
			Version:  p.Version,
			IsDirect: deps[root],
		})
	}
	return inputs
}
