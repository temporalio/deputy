// Package analysis provides OSV vulnerability database integration for Deputy.
//
// The osv subpackage contains the canonical types and functions for querying
// the OSV database and processing vulnerability results:
//   - osv.PkgInput: package query input
//   - osv.Vulnerability: raw OSV query result
//   - osv.QueryOSVBatch: batch vulnerability queries
//   - osv.Client: client interface for OSV API
//
// Downstream processing (consolidation, severity classification, reporting)
// is handled by internal/vulnerability and internal/scan.
package analysis
