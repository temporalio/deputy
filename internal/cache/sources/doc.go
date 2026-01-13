// Package sources provides cache.Source implementations for Deputy's data sources.
//
// Each source wraps an external data provider and implements the cache.Source interface,
// enabling unified cache management through the cache.Registry.
//
// # Bulk-Downloaded Sources
//
// These sources download complete datasets that can be used offline:
//
//   - [OSVSource]: OSV vulnerability database (GitHub Actions ecosystem).
//     Downloads a ZIP archive from Google Cloud Storage with ~6 hour TTL.
//
//   - [KEVSource]: CISA Known Exploited Vulnerabilities catalog.
//     Downloads the full JSON catalog with ~1 hour TTL.
//
// # On-Demand Sources
//
// These sources are populated incrementally as data is requested:
//
//   - [EPSSSource]: FIRST EPSS exploitation probability scores.
//     Cached per-CVE with ~24 hour TTL. Status shows aggregate statistics.
//
//   - [DepsDevSource]: deps.dev license and dependency data.
//     Cached per-package with ~7 day TTL. Status shows aggregate statistics.
//
// # Usage
//
// Sources are typically registered with a cache.Registry:
//
//	reg := cache.NewRegistry()
//	reg.Register(sources.NewOSVSource())
//	reg.Register(sources.NewKEVSource())
//	reg.Register(sources.NewEPSSSource())
//	reg.Register(sources.NewDepsDevSource())
//
// The registry provides bulk operations for status, populate, and clear.
//
// # Adding New Sources
//
// To add a new cacheable data source:
//
//  1. Create a new file (e.g., nvd.go) implementing cache.Source
//  2. Define source constants (name, description, TTL, URLs)
//  3. Implement Status(), Populate(), and Clear() methods
//  4. Add OpenTelemetry tracing spans for Populate operations
//  5. Add structured logging (slog) for key operations
//  6. Register the source in the CLI's buildRegistry()
package sources
