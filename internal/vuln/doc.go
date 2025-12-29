// Package vuln defines Deputy's vulnerability domain model and scoring helpers.
//
// It contains stable value types (vulnerability records, manifest references),
// severity parsing/classification, CVSS score parsing, and consolidation logic
// (alias grouping, best-fix selection). The package is intentionally pure: no
// network calls, filesystem access, or global state. This keeps the domain
// composable, testable, and safe to reuse across CLI, proxy, and remediation.
package vuln
