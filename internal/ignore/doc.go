// Package ignore provides vulnerability suppression rules for Deputy scans.
//
// The ignore package enables users to suppress specific vulnerability findings
// based on ID, package name, or ecosystem. Rules can be defined in YAML files
// and optionally have expiration dates.
//
// # File Formats
//
// Rules can be defined in several file formats, auto-discovered from:
//   - .deputy.yaml (ignore section in main config)
//   - .deputyignore.yaml (standalone ignore file)
//   - deputy-baseline.yaml (baseline suppressions)
//
// Example standalone ignore file (.deputyignore.yaml):
//
//	ignore:
//	  - id: CVE-2021-44228
//	    reason: Not exploitable in our environment
//	  - package: lodash
//	    until: "2025-12-31"
//	    reason: Scheduled for removal
//	  - ecosystem: deprecated
//	    reason: Legacy ecosystem
//
// # Rule Matching
//
// Rules support several matching criteria:
//   - id: Match by vulnerability ID (CVE, GHSA, etc.)
//   - package: Match by package name (supports wildcards like "github.com/user/*")
//   - ecosystem: Match by ecosystem (go, npm, pypi, etc.)
//
// Multiple criteria in a single rule are AND-ed together.
// Rules across the ignore list are OR-ed.
//
// # Expiration
//
// Rules can have an optional "until" field specifying when the rule expires.
// Expired rules are not applied during scans.
//
//	ignore:
//	  - id: CVE-2024-1234
//	    until: "2025-06-01"  # Rule expires after this date
//	    reason: Temporary suppression while fix is deployed
//
// # Baselines
//
// Baselines capture a point-in-time snapshot of known vulnerabilities,
// useful for tracking new vulnerabilities against a known state.
// Baseline files are automatically converted to ignore rules.
package ignore
