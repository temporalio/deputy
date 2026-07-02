// Example Deputy advisory-source plugin.
//
// It demonstrates how to extend Deputy's vulnerability lookup with a custom
// source (a threat feed, vendor database, internal allow/deny list, …) using
// the Deputy plugin SDK. This example serves a single static advisory so the
// wiring is easy to follow; a real plugin would query an upstream API.
//
// # Building
//
//	go build -o deputy-advisory-source-static ./examples/advisory-source-plugins/static
//
// # Usage with Deputy
//
// Place the built binary on PATH named "deputy-advisory-source-static"; Deputy
// discovers advisory-source plugins by that prefix and aggregates their results
// with the built-in OSV source (union-with-provenance). A plugin must declare
// accurate capabilities: Deputy routes only packages it covers.
package main

import (
	"context"

	plugin "github.com/temporalio/deputy/sdk/plugin"
)

// staticSource reports one hard-coded malicious npm package, purely to
// demonstrate the AdvisorySource contract end to end.
type staticSource struct{}

const advisoryID = "MAL-EXAMPLE-0001"

func (s *staticSource) Info() *plugin.AdvisorySourceInfo {
	return &plugin.AdvisorySourceInfo{
		Name:        "static-example",
		DisplayName: "Static Example Source",
		Description: "Example advisory source that flags a single known-bad package.",
		Version:     1,
		Capabilities: &plugin.SourceCapabilities{
			Ecosystems:   []string{"npm"},
			Artifacts:    []plugin.ArtifactKind{plugin.ArtifactKindPackage},
			FindingKinds: []plugin.FindingKind{plugin.FindingKindMalware},
		},
	}
}

func (s *staticSource) Query(_ context.Context, packages []*plugin.Package) ([]*plugin.Finding, map[string]*plugin.Advisory, error) {
	var findings []*plugin.Finding
	advisories := map[string]*plugin.Advisory{}
	for _, pkg := range packages {
		if pkg.GetName() != "evil-package" {
			continue
		}
		findings = append(findings, &plugin.Finding{
			AdvisoryId: advisoryID,
			Package:    pkg,
			Affected:   true,
		})
		advisories[advisoryID] = &plugin.Advisory{
			Id:      advisoryID,
			Summary: "evil-package is malicious",
			Kind:    plugin.FindingKindMalware,
		}
	}
	return findings, advisories, nil
}

func main() {
	plugin.MainAdvisorySource(&staticSource{})
}
