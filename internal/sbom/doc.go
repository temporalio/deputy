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
//
// Custom Properties:
// Deputy injects custom metadata into the SBOM properties to preserve context
// that is not natively supported by the core Protobom model or is specific to
// Deputy's remediation engine.
//
//   - "deputy:direct": "true" if the package is a direct dependency.
//   - "deputy:location": The file path (e.g. "go.mod") where the dependency was found.
//     This property may appear multiple times if a package is referenced in multiple locations.
//   - "deputy:metadata.<key>": Structured metadata for ecosystems that emit a stable schema
//     (e.g. Terraform requirements). List values are repeated with the same key.
package sbomx
