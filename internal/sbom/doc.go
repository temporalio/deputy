// Package sbomx generates Software Bills of Materials (SBOM) for local or
// remote repositories and can optionally enrich component nodes with license
// metadata. The primary output currently targets the Protobom intermediate
// model, providing a neutral representation that can later be serialized into
// SPDX, CycloneDX, or custom formats.
//
// Key responsibilities:
//   - Repository acquisition (local path vs remote clone on-demand)
//   - Inventory collection at an exact ref (HEAD~0 canonicalization)
//   - Construction of a normalized node graph with stable identifiers (PURLs)
//   - Optional license enrichment strategies (deps.dev, static scanning)
//
// The Generate function is the orchestration entry point returning an in-memory
// Protobom document for further serialization or analysis.
package sbomx
