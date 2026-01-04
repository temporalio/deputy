// Package dependency provides types for identifying dependencies and their locations.
//
// This package contains the core types that describe what a dependency is and where
// it was found, independent of vulnerability analysis:
//
//   - [ID]: Identity of a dependency (name, ecosystem, PURL)
//   - [ManifestRef]: Where a dependency is declared in source (manifest path, manager)
//   - [LayerDetails]: Where a dependency was found in a container image (layer info)
//
// These types are used throughout Deputy to track dependencies from extraction
// through vulnerability analysis and reporting.
package dependency

// ID captures the identity of a dependency independently of a scan.
type ID struct {
	Name      string
	Ecosystem string
	PURL      string
}

// ManifestRef describes where a dependency is declared in a manifest or lockfile.
type ManifestRef struct {
	Path    string
	Manager string
	Groups  []string
}

// LayerDetails describes the container image layer where a package was found.
// This information is populated when scanning container images and enables
// layer-aware analysis, base image detection, and layer-specific policy evaluation.
type LayerDetails struct {
	// Index is the position of the layer in the image (0 = oldest/base layer).
	Index int `json:"index"`
	// DiffID is the digest of the uncompressed layer content.
	DiffID string `json:"diffId,omitempty"`
	// ChainID is the cumulative hash identifying this layer in context of its parents.
	// See: https://github.com/opencontainers/image-spec/blob/main/config.md#layer-chainid
	ChainID string `json:"chainId,omitempty"`
	// Command is the Dockerfile instruction that created this layer (e.g., "RUN apt-get install...").
	Command string `json:"command,omitempty"`
	// InBaseImage indicates whether this layer is part of the base image (FROM instruction).
	InBaseImage bool `json:"inBaseImage,omitempty"`
}
