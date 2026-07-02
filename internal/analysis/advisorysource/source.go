package advisorysource

import (
	"context"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	pluginv1 "github.com/temporalio/deputy/gen/deputy/plugin/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

// Source is an advisory provider: given packages, it returns the advisories
// (vulnerabilities and malware) affecting them. The built-in OSV source and
// future plugin sources both satisfy this interface and exchange the same proto
// types, so they are interchangeable to a [Registry].
//
// Implementations must ignore packages outside their declared Capabilities
// rather than erroring; the Registry only routes covered packages to them, but
// a defensive skip keeps a misconfigured source from failing an aggregate scan.
type Source interface {
	// Info returns the source's identity and declared coverage.
	Info() *pluginv1.AdvisorySourceInfo
	// Query returns the advisories affecting pkgs.
	Query(ctx context.Context, pkgs []*dependencyv1.Package) (*Result, error)
}

// Result is a single source's answer: findings plus the full advisory records
// they reference, keyed by advisory ID.
type Result struct {
	Findings   []*vulnerabilityv1.Finding
	Advisories map[string]*vulnerabilityv1.Advisory
}
