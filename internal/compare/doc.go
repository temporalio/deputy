// Package compare provides routines for normalizing Go module/package import paths
// and computing semantic changes between two package inventories. It focuses on
// practical diffing of Go dependencies across Git references, including
// canonicalization of multi-major version module paths (e.g. /v2 suffixes) and
// translation of historical gopkg.in vanity hosts to their GitHub equivalents.
//
// The core entry point, ComparePackages, produces a set of Change records that
// categorize dependency transitions as Added, Removed, Upgraded, Downgraded,
// or Updated (non-semver changes) while preserving whether a dependency is
// direct (appears explicitly in go.mod) or indirect. Helper functions handle:
//   - Path canonicalization (NormalizeGopkgInURL, ExtractCanonicalPackageName)
//   - Parsing import paths into structured GoPackageInfo (ParseGoPackage)
//   - Semantic version comparison with proper v-prefix handling
//
// These utilities enable higher‑level commands (e.g. the CLI diff command) to
// present human and machine-friendly dependency delta reports and drive
// downstream workflows like vulnerability or license analysis.
package compare
