// Package osv provides OSV integration and conversion into Deputy's
// vulnerability domain types. It owns:
//   - OSV API batch queries and vulnerability expansion
//   - GitHub Actions bucket ingestion and version resolution
//   - Cache-aware lookups and conversion into internal/vuln models
//
// This package is integration-focused; callers should rely on internal/vuln
// for domain logic and internal/analysis for orchestration facades.
package osv
