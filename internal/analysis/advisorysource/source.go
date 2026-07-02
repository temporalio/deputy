package advisorysource

import (
	"context"

	pluginv1 "github.com/temporalio/deputy/gen/deputy/plugin/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// Source is an advisory provider: given package query inputs, it returns the
// advisories (vulnerabilities and malware) affecting them.
//
// The interface is domain-typed (osv.PkgInput in, vulnerability.Finding out) so
// the in-process scan path stays lossless — proto findings cannot carry
// direct/indirect classification, which stats and remediation depend on. The
// proto AdvisorySourceService is the plugin wire contract; a plugin adapter
// bridges proto<->domain, exactly as inventory extractor plugins are adapted to
// the in-process extractor interface. Info() returns the proto capability
// descriptor shared by built-in and plugin sources.
type Source interface {
	// Info returns the source's identity and declared coverage.
	Info() *pluginv1.AdvisorySourceInfo
	// Query returns the advisories affecting pkgs. Implementations must ignore
	// inputs outside their declared Capabilities rather than erroring.
	Query(ctx context.Context, pkgs []osv.PkgInput) (*Result, error)
}

// Result is a single source's answer: findings plus the full advisory records
// they reference, keyed by advisory ID.
type Result struct {
	Findings   []vulnerability.Finding
	Advisories map[string]*vulnerabilityv1.Advisory
}
