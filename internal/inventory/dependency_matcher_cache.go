package inventory

import (
	"slices"
	"strings"
	"sync"
)

var matcherCache sync.Map // map[string]*DependencyMatcher

// GetDependencyMatcher returns a DependencyMatcher for the provided scan
// options, caching instances so repeated calls avoid re-instantiating the
// underlying osv-scalibr plugins. The cache key is derived from the normalized
// ecosystem list (with "all" collapsing to a single entry).
func GetDependencyMatcher(opts ScanOptions) (*DependencyMatcher, error) {
	key := matcherCacheKey(opts)
	if val, ok := matcherCache.Load(key); ok {
		return val.(*DependencyMatcher), nil
	}
	matcher, err := NewDependencyMatcher(opts)
	if err != nil {
		return nil, err
	}
	matcherCache.Store(key, matcher)
	return matcher, nil
}

// matcherCacheKey normalizes the provided scan options into a deterministic key
// so that equivalent ecosystem sets (ignoring order, duplicates, or "all")
// share the same cached matcher instance.
func matcherCacheKey(opts ScanOptions) string {
	if len(opts.Ecosystems) == 0 {
		return "all"
	}
	normalized := make([]string, 0, len(opts.Ecosystems))
	for _, raw := range opts.Ecosystems {
		trimmed := strings.ToLower(strings.TrimSpace(raw))
		if trimmed == "" || trimmed == "all" {
			continue
		}
		normalized = append(normalized, trimmed)
	}
	if len(normalized) == 0 {
		return "all"
	}
	slices.Sort(normalized)
	normalized = slices.Compact(normalized)
	return strings.Join(normalized, ",")
}
