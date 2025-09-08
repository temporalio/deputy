// Package analysis consolidates and enriches vulnerability data for Go
// dependencies. It provides:
//   - Data model types (Vulnerability, ConsolidatedVulnerability, VulnerabilityStats)
//   - Adapters for querying the OSV API in efficient batches (QueryOSVBatch)
//   - Normalization logic that selects stable identifiers (CVE over GO-/GHSA-)
//   - Extraction of severity, references, and fixed version metadata
//
// The package is intentionally light on external assumptions so it can be used
// both by human‑oriented CLI presentation layers and machine consumers
// (e.g. JSON reporters, CI policy gates). All exported types are stable value
// objects whose fields are designed for long‑term backwards compatibility.
package analysis
