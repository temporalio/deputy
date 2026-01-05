// Package osv provides OSV integration and conversion into Deputy's
// vulnerability domain types. It owns:
//   - OSV API batch queries and vulnerability expansion
//   - GitHub Actions bucket ingestion and version resolution
//   - Conversion into internal/vulnerability domain models
//
// This package is integration-focused; callers should rely on
// internal/vulnerability for domain logic.
package osv
