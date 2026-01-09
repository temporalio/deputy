// Package analysis provides OSV vulnerability database integration for Deputy.
//
// The osv subpackage contains the canonical types and functions for querying
// the OSV database and processing vulnerability results:
//   - osv.PkgInput: package query input
//   - osv.Query: batch queries returning domain types (findings + advisories)
//   - osv.QueryRaw: batch queries returning flat Vulnerability records
//   - osv.Client: client interface for OSV API
//
// Downstream processing (consolidation, severity classification, reporting)
// is handled by internal/vulnerability and internal/scanning.
package analysis
