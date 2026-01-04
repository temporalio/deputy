// Package license provides license lookup and enrichment helpers for Deputy.
//
// It combines deps.dev metadata, registry lookups, and best-effort scans of
// module archives or repositories to surface SPDX identifiers. The package
// is IO-heavy by design and maintains memoization and on-disk caching (via
// [github.com/picatz/deputy/internal/cache/disk]) to keep repeated lookups fast and reliable.
package license
