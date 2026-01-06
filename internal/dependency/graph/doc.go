// Package graph provides dependency graph construction, analysis, and visualization.
//
// A dependency graph represents the relationships between packages in a software
// project. Nodes represent packages, and directed edges represent "depends on"
// relationships (from dependent to dependency).
//
// # Graph Construction
//
// Graphs can be constructed from multiple sources:
//
//   - Inventory extraction: [FromInventory] creates a graph from extracted packages,
//     but without edge information (suitable for flat listing).
//
//   - Lockfile parsing: Ecosystem-specific [EdgeResolver] implementations parse
//     lockfiles to extract dependency relationships. The [ResolverRegistry] provides
//     a unified interface for multi-ecosystem resolution:
//
//     | Ecosystem    | Resolver           | Lockfile(s)                           | Strategy                    |
//     |--------------|--------------------|-----------------------------------------|-----------------------------|
//     | Go           | [GoResolver]       | go.mod                                 | vendor -> proxy -> git      |
//     | npm          | [NpmResolver]      | package-lock.json, npm-shrinkwrap.json | parse lockfile tree         |
//     | Cargo        | [CargoResolver]    | Cargo.lock                             | parse lockfile              |
//     | PyPI         | [PyPIResolver]     | poetry.lock, uv.lock, requirements.txt | parse lockfile or flat list |
//     | RubyGems     | [RubyGemsResolver] | Gemfile.lock                           | parse lockfile              |
//
//   - SBOM import: Parse CycloneDX/SPDX relationship data to reconstruct edges.
//
//   - Container images: Layer attribution provides implicit relationships between
//     packages and the layers that introduced them.
//
// # Analysis Operations
//
// Once constructed, graphs support several analysis operations:
//
//   - Path finding: [Graph.PathsTo] finds all paths from root to a target package,
//     answering "why is X in my dependencies?" (analogous to `go mod why`).
//
//   - Reverse lookup: [Graph.Ancestors] finds all packages that depend on a target,
//     answering "what depends on X?" (useful for vulnerability impact analysis).
//
//   - Subgraph extraction: [Graph.Subgraph] extracts a subtree rooted at a package,
//     answering "what does X bring in?"
//
//   - Vulnerability annotation: [Graph.AnnotateVulns] attaches vulnerability findings
//     to affected nodes for security-focused visualization.
//
// # Visualization
//
// Graphs can be rendered to multiple formats via [Graph.Render]:
//
//   - FormatText: ASCII tree view (CLI-friendly)
//   - FormatDOT: Graphviz DOT format
//   - FormatMermaid: Mermaid.js flowchart
//   - FormatD3: D3.js force-directed graph JSON
//   - FormatJSON: Full graph structure as JSON
//
// Render options control output:
//
//   - [WithMaxDepth]: Limit tree depth
//   - [WithHighlightVulns]: Style vulnerable nodes
//   - [WithFilter]: Include only matching nodes
//
// # Architecture
//
// The graph subsystem is designed around these principles:
//
//  1. Ecosystem-agnostic core: The [Graph], [Node], and [Edge] types work across
//     all ecosystems. Ecosystem-specific logic lives in [EdgeResolver] implementations.
//
//  2. Incremental construction: Graphs can be built incrementally, adding nodes
//     from inventory extraction first, then edges from lockfile parsing.
//
//  3. Target-polymorphic: The same graph types work for directories, git repos,
//     container images, SBOMs, and individual PURLs.
//
//  4. Offline-first: Edge resolution should work from local lockfiles without
//     network calls when possible. deps.dev API is a fallback for ecosystems
//     without parseable lockfiles.
//
// # Thread Safety
//
// Graph instances are not safe for concurrent modification. However, read
// operations (queries, iteration, rendering) can be performed concurrently
// after construction is complete.
package graph
