package osv

import "github.com/picatz/deputy/internal/vuln"

// Domain type aliases for OSV integration.
type (
	Vulnerability     = vuln.Vulnerability
	ManifestReference = vuln.ManifestReference
	AffectedImport    = vuln.AffectedImport
)
