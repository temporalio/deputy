// Package filtering provides filter functions for scan results.
//
// All functions operate directly on proto types (scanv1.ScanResponse).
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
