package analysis

import (
	"context"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/picatz/deputy/internal/analysis/osv"
	"osv.dev/bindings/go/osvdev"
)

// OSVClient abstracts the subset of osv.dev client functionality required for
// batch querying and vulnerability expansion.
type OSVClient = osv.OSVClient

// PkgInput represents a single package@version query for OSV.
type PkgInput = osv.PkgInput

// PkgInputLayerDetails stores layer details for package input (from SCALIBR).
// This is the input-side type; use LayerDetails (from vuln package) for output.
type PkgInputLayerDetails = osv.LayerDetails

// NewOSVClient returns an osv.dev client configured with production-friendly HTTP timeouts
// and automatic retry for transient failures.
func NewOSVClient() *osvdev.OSVClient {
	return osv.NewOSVClient()
}

// QueryOSVBatch performs a batched OSV vulnerability lookup for the provided packages.
func QueryOSVBatch(ctx context.Context, client OSVClient, pkgs []PkgInput) ([]Vulnerability, error) {
	return osv.QueryOSVBatch(ctx, client, pkgs)
}

// ProcessOSVVulnerability converts a raw OSV schema vulnerability into the
// internal Vulnerability representation scoped to a specific package@version.
func ProcessOSVVulnerability(vuln osvschema.Vulnerability, input PkgInput) Vulnerability {
	return osv.ProcessOSVVulnerability(vuln, input)
}
