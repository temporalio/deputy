// Package filtering provides proto-native filter functions for scan results.
//
// All functions operate directly on proto types (scanv1.ScanResponse),
// eliminating conversion overhead. This is part of the proto-first
// architecture where proto types are the canonical data representation.
//
// # Filter Functions
//
// FilterUnfixed removes findings without available fixes:
//
//	filtered := filtering.FilterUnfixed(resp)
//
// FilterIgnored removes findings matching ignore rules:
//
//	filtered, count := filtering.FilterIgnored(resp, rules)
//
// Merge combines multiple scan responses:
//
//	merged := filtering.Merge(base, extra)
//
// All filter functions return new responses (immutable pattern) with
// recomputed stats.
package filtering
