// Package inventory extracts a dependency inventory (package list) from either
// the current working tree or a historical commit snapshot. It leverages
// google/osv-scalibr plugins to perform language/ecosystem aware scanning.
//
// Two entry points are provided:
//   - ScanPackagesWorking – analyzes the present filesystem state without mutating Git
//   - ScanPackagesAtCommitSnapshot – materializes a commit into a temp directory for scanning
//
// The abstractions are intentionally narrow: callers receive raw scalibr
// Package objects and can layer additional classification or enrichment.
package inventory
