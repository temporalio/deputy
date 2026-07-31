package advisorysource

import (
	"context"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	pluginv1 "github.com/temporalio/deputy/gen/deputy/plugin/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

// Source is an advisory provider: given packages, it returns the advisories
// (vulnerabilities and malware) affecting them.
//
// The interface is proto-first: a source consumes and produces exactly the
// proto types that cross the plugin wire, so the built-in OSV source and an
// external pluginrpc source are interchangeable with no adapter or lossy
// conversion. Info() is the same proto capability descriptor both advertise.
type Source interface {
	// Info returns the source's identity and declared coverage.
	Info() *pluginv1.AdvisorySourceInfo
	// Query returns the advisories affecting pkgs. Implementations must ignore
	// packages outside their declared Capabilities rather than erroring.
	Query(ctx context.Context, pkgs []*dependencyv1.Package) (*Result, error)
}

// Result is a single source's answer: findings plus the full advisory records
// they reference, keyed by advisory ID.
type Result struct {
	Findings   []*vulnerabilityv1.Finding
	Advisories map[string]*vulnerabilityv1.Advisory
}
