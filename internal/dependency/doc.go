// Package dependency provides core types for representing software dependencies.
//
// This package defines the fundamental data structures used throughout Deputy
// for modeling dependencies across different ecosystems (Go, npm, PyPI, etc.).
//
// # Core Types
//
// [ID] uniquely identifies a dependency by name, version, ecosystem, and PURL.
// It serves as the canonical identifier used in scan results and findings.
//
// [ManifestRef] tracks where a dependency was declared, including the file path,
// package manager, and dependency groups (e.g., "dev", "optional").
//
// [LayerDetails] provides container image layer information for dependencies
// found during image scanning, including the layer index, digest, and
// Dockerfile command that introduced the package.
//
// # Clone Functions
//
// The package provides deep clone utilities for safely copying types that
// contain slices, ensuring mutations to clones don't affect originals:
//
//   - [CloneLayerDetails] - deep copy of LayerDetails
//   - [CloneManifestRefs] - deep copy of ManifestRef slice
package dependency
