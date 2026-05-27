// Package dependency provides types for identifying dependencies and their locations.
//
// This package contains the core types that describe what a dependency is and where
// it was found, independent of vulnerability analysis:
//
//   - [ID]: Identity of a dependency (name, ecosystem, PURL)
//   - [dependencyv1.ManifestRef]: Where a dependency is declared in source (manifest path, manager)
//   - [containerv1.LayerDetails]: Where a dependency was found in a container image (layer info)
//
// These types are used throughout Deputy to track dependencies from extraction
// through vulnerability analysis and reporting.
package dependency

import (
	"slices"

	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
)

// ID captures the identity of a dependency independently of a scan.
type ID struct {
	Name      string
	Ecosystem string
	PURL      string
}

// CloneLayerDetails returns a deep copy of LayerDetails.
// Returns nil if src is nil.
func CloneLayerDetails(src *containerv1.LayerDetails) *containerv1.LayerDetails {
	if src == nil {
		return nil
	}
	return &containerv1.LayerDetails{
		Index:       src.Index,
		DiffId:      src.DiffId,
		ChainId:     src.ChainId,
		Command:     src.Command,
		InBaseImage: src.InBaseImage,
	}
}

// CloneManifestRefs deep clones a slice of ManifestRef.
// Returns nil if refs is empty or nil.
func CloneManifestRefs(refs []dependencyv1.ManifestRef) []dependencyv1.ManifestRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]dependencyv1.ManifestRef, len(refs))
	for i, ref := range refs {
		out[i] = dependencyv1.ManifestRef{
			Path:    ref.Path,
			Manager: ref.Manager,
			Groups:  slices.Clone(ref.Groups),
		}
	}
	return out
}
