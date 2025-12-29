// Package analysis orchestrates vulnerability enrichment and provides a
// compatibility facade for higher-level callers.
//
// Responsibilities:
//   - Coordinate scan analysis workflows (filtering, grouping, reporting inputs)
//   - Expose stable aliases to the vulnerability domain types
//   - Route OSV integration through internal/analysis/osv
//
// Pure domain logic (types, CVSS parsing, severity classification, grouping)
// lives in internal/vuln. Service integrations live in subpackages such as
// internal/analysis/osv and internal/license.
package analysis
