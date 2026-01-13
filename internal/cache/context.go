package cache

import (
	"context"
	"slices"
	"strings"
)

// Context keys for cache bypass functionality.
type (
	bypassAllKey     struct{}
	bypassSourcesKey struct{}
)

// WithBypassAll returns a context that signals all caches should be bypassed.
// Use this when the user specifies --no-cache without specific sources.
func WithBypassAll(ctx context.Context) context.Context {
	return context.WithValue(ctx, bypassAllKey{}, true)
}

// WithBypassSources returns a context that signals specific caches should be bypassed.
// Sources is a list of source names (e.g., "osv", "kev", "epss").
func WithBypassSources(ctx context.Context, sources []string) context.Context {
	return context.WithValue(ctx, bypassSourcesKey{}, sources)
}

// ShouldBypass returns true if all caches should be bypassed.
func ShouldBypass(ctx context.Context) bool {
	v, _ := ctx.Value(bypassAllKey{}).(bool)
	return v
}

// ShouldBypassSource returns true if the specified source should be bypassed.
// It returns true if:
// - ShouldBypass(ctx) is true (all caches bypassed), or
// - The source name is in the list of bypassed sources
func ShouldBypassSource(ctx context.Context, source string) bool {
	// Check if all caches are bypassed
	if ShouldBypass(ctx) {
		return true
	}

	// Check if this specific source is bypassed
	sources, _ := ctx.Value(bypassSourcesKey{}).([]string)
	return slices.Contains(sources, source)
}

// BypassedSources returns the list of sources that should be bypassed,
// or nil if all caches are bypassed or no specific sources are set.
func BypassedSources(ctx context.Context) []string {
	sources, _ := ctx.Value(bypassSourcesKey{}).([]string)
	return sources
}

// ParseNoCacheFlag parses the --no-cache flag value.
// - Empty string or "true" means bypass all caches.
// - "false" means don't bypass any caches.
// - Comma-separated values specify which sources to bypass.
//
// Returns:
// - bypassAll: true if all caches should be bypassed
// - sources: list of source names to bypass (empty if bypassAll is true)
func ParseNoCacheFlag(value string) (bypassAll bool, sources []string) {
	value = strings.TrimSpace(value)

	switch value {
	case "", "true":
		return true, nil
	case "false":
		return false, nil
	default:
		// Parse comma-separated source names
		parts := strings.Split(value, ",")
		sources = make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				sources = append(sources, p)
			}
		}
		return false, sources
	}
}

// ApplyNoCacheFlag applies the parsed --no-cache flag to the context.
func ApplyNoCacheFlag(ctx context.Context, value string) context.Context {
	bypassAll, sources := ParseNoCacheFlag(value)

	if bypassAll {
		return WithBypassAll(ctx)
	}
	if len(sources) > 0 {
		return WithBypassSources(ctx, sources)
	}
	return ctx
}
