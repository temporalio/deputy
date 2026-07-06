// Package mcp provides a Model Context Protocol server for Deputy.
//
// The MCP server exposes Deputy's dependency analysis and vulnerability scanning
// capabilities to AI assistants and other tools that support the MCP protocol.
//
// # Available Tools
//
// The server provides the following tools:
//
// ## Server and Policy Metadata
//
//   - get_server_info: Get server build, process, and tool metadata
//   - list_policy_entrypoints: List CEL policy entrypoints, variables, and helpers
//
// ## Vulnerability Analysis
//
//   - explain_vulnerability: Get detailed information about a CVE/GHSA by ID
//   - explain_vulnerabilities: Get details about multiple vulnerabilities at once
//   - scan_package: Check a single package for known vulnerabilities
//   - scan_directory: Scan a directory for vulnerabilities in all dependencies
//   - scan_container: Scan a container image for vulnerabilities
//   - triage_vulnerabilities: Prioritize and summarize vulnerabilities for remediation
//
// ## Dependency Analysis
//
//   - list_dependencies: List all dependencies in a directory with metadata
//   - analyze_dependency_graph: Analyze dependency graph and find paths to vulnerable packages
//   - graph_why: Show why a package is in the dependency graph (like 'go mod why')
//   - graph_needs: Show what packages depend on a given package (reverse dependency lookup)
//
// ## Comparison
//
//   - diff_refs: Compare dependencies between Git refs or container images
//
// ## SBOM Generation
//
//   - generate_sbom: Generate Software Bill of Materials in CycloneDX, SPDX, or Protobom format
//
// ## Remediation
//
//   - get_remediation: Get actionable commands to fix vulnerabilities
//
// # Tool Contracts
//
// Every tool's input and output contract is a deputy.mcp.v1 proto message
// (api/deputy/mcp/v1/mcp.proto). The advertised JSON Schemas are derived from
// the proto descriptors at registration time (see internal/mcp/protoschema),
// requests are enforced against the same buf.validate rules the schemas
// advertise, and the SDK validates every result against its output schema, so
// the schema, the wire, and the server cannot drift apart. Results are
// protojson with camelCase names. Assessment tools honor the target's
// vulnerability suppressions (.deputyignore.yaml and friends), exactly like
// the CLI: suppressed findings are excluded and counted in ignoredCount.
// Zero values of plain fields are omitted, so
// an absent field means empty, none, or not applicable; affirmative answers
// (found, clean, direct, hasFix, migration, executable, depth,
// isContainerDiff) use proto3 optional and are on the wire whenever they
// apply, even when false or zero. When an answer does not apply it stays
// absent: a graph result's direct is absent when the package was not found.
//
// # Running the Server
//
// The MCP server can be started via the CLI:
//
//	deputy mcp serve
//
// Or programmatically:
//
//	server := mcp.NewServer()
//	server.Run(ctx)
//
// # Server Options
//
// The server uses the services layer for all operations, ensuring consistency
// with CLI, API, and plugins. Configure with WithServices for best practice:
//
//	svc, _ := services.New()
//	server := mcp.NewServer(mcp.WithServices(svc))
//
// For testing, use WithClients with mock service clients:
//
//	mockClients := &services.Clients{...}
//	server := mcp.NewServer(mcp.WithClients(mockClients))
//
// # Integration with AI Tools
//
// The MCP server communicates over stdio, making it compatible with:
//   - Claude Desktop
//   - Any MCP-compatible AI assistant
//   - Custom integrations using the MCP protocol
//
// # Example Usage (Claude Desktop config)
//
//	{
//	  "mcpServers": {
//	    "deputy": {
//	      "command": "deputy",
//	      "args": ["mcp", "serve"]
//	    }
//	  }
//	}
//
// # Tool Details
//
// ## get_server_info
//
// Returns build and process metadata for the running Deputy MCP server. Agents
// should call this when verifying that a restarted MCP process picked up a new
// local build. The response includes the Deputy version, process ID, start time,
// registered tools, and configured default exclude paths.
//
// ## list_policy_entrypoints
//
// Lists Deputy's CEL policy entrypoints with their categories, bound
// variables, and helper functions, for authoring policies. Accepts an
// optional category filter (legacy aliases container, service, and exec are
// normalized). The entrypoint metadata comes from the same registry that
// powers the policy API and the generated policy-inputs reference.
//
// ## explain_vulnerability
//
// Retrieves full advisory details for one vulnerability ID. referenceLimit
// optionally caps the returned reference list; omit it or pass a negative value
// for all references, or pass 0 to omit references while keeping
// referenceCount/referencesTruncated metadata.
//
// ## explain_vulnerabilities
//
// Retrieves full advisory details for multiple IDs with partial-success
// semantics. Found advisories are returned in input order. Missing IDs are
// reported as stable per-ID not-found strings instead of raw upstream OSV HTTP
// response bodies. referenceLimit has the same per-vulnerability semantics as
// explain_vulnerability.
//
// ## scan_package
//
// Checks one package version for known vulnerabilities. Prefer purl when the
// package came from another Deputy MCP result; split name/version/ecosystem
// fields are supported for manually entered packages. The result contains
// compact vulnerability summaries; call explain_vulnerability with an ID when
// the full advisory details or complete reference list are needed. Severity is
// a canonical CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN label, and timestamps are RFC3339
// when present. Vulnerability arrays are ordered by severity, directness,
// fixability, and stable package/ID tie-breakers.
//
// Input:
//   - purl: Optional Package URL, e.g. "pkg:npm/lodash@4.17.21"
//   - name: Package name, or a pkg: PURL when purl is not set
//   - version: Package version, required unless purl or name includes @version
//   - ecosystem: Package ecosystem, required unless purl is provided
//
// ## scan_directory
//
// Scans a local directory for vulnerabilities by analyzing dependency manifests
// (go.mod, package.json, requirements.txt, etc.). Returns vulnerability counts
// by severity and compact information about each finding. The severity map
// includes an unknown bucket so counts sum to the total; scanTime is a human
// string and scanTimeMs the machine-readable elapsed milliseconds; each finding
// carries severityType (the scoring system, e.g. CVSS_V3), sources (advisory
// provenance), and kind (malware vs vulnerability) when known. A coverage block
// reports which (ecosystem, artifact) combinations an advisory source answered
// for and which had none (e.g. container base images); uncovered means
// not-checked, not safe.
//
// Input:
//   - path: Path to the directory to scan (required)
//   - ref: Optional Git reference, branch, tag, or commit for repository paths
//   - ecosystems: Optional list of ecosystems to scan (e.g., ["go", "npm"])
//   - excludePaths: Optional directory globs to skip during filesystem walks
//
// For Git repository snapshots, output echoes ref, effectiveRef, and commit
// when Deputy's target resolver provides that metadata.
//
// ## scan_container
//
// Scans a container image for vulnerabilities. Supports remote registries,
// local Docker daemon images, and various transport schemes.
//
// Input:
//   - image: Container image reference (e.g., "nginx:1.25", "ghcr.io/owner/app:v1", "docker-daemon://myapp:latest")
//   - platform: Target platform (e.g., "linux/amd64"). Defaults to current platform.
//
// ## list_dependencies
//
// Lists all dependencies discovered in a directory. Supports filtering to
// show only direct dependencies.
//
// Input:
//   - path: Path to the directory (required)
//   - directOnly: If true, only return direct dependencies
//   - ref: Optional Git reference, branch, tag, or commit for repository paths
//   - ecosystems: Optional ecosystem filter
//   - excludePaths: Optional directory globs to skip during filesystem walks
//
// Output counts:
//   - total/direct/transitive count returned dependencies after filters
//   - totalDiscovered/directDiscovered/transitiveDiscovered count the full
//     discovered inventory before the directOnly display filter
//   - dependencies[].manifestRefs preserves structured source identity,
//     including package manager, dependency groups, and the original manifest
//     component key when it differs from the vulnerability package name
//   - dependencies are sorted by PURL, then directness, name, version, and
//     ecosystem for stable repeated agent calls
//   - ref/effectiveRef/commit echo Git snapshot identity when available
//
// ## generate_sbom
//
// Generates a Software Bill of Materials for a local directory or repository
// checkout.
// Supports CycloneDX, SPDX, and Protobom JSON formats.
//
// Input:
//   - path: Local directory or local repository checkout (required)
//   - ref: Git reference (branch, tag, commit). Defaults to HEAD.
//   - format: Output format (cyclonedx-json, spdx-json, protobom-json; the
//     short aliases cyclonedx, spdx, protobom are equivalent)
//   - enrichLicenses: Enable license enrichment from deps.dev
//   - excludePaths: Optional directory globs to skip during filesystem walks
//
// ## get_remediation
//
// Scans a directory and returns the agent-facing projection of a
// deputy.remediation.v1 remediation plan, generated by the same
// RemediationService.GeneratePlan producer the API and agent flows use. Each
// step classifies the remediation (kind), links the finding IDs it addresses
// (affectedVulnerabilities), and carries package identity (purl) so agents
// can follow up with graph_why without parsing command text. Indirect
// migration hints tell agents when graph_why needs resolveTransitives
// enabled; hints are adapted for MCP tools rather than CLI-only flags. Stats
// report addressed and unaddressed finding counts separately from step
// counts because several findings can share one deduplicated step.
//
// Input:
//   - path: Path to the directory (required)
//   - ref: Optional Git reference, branch, tag, or commit for repository paths
//   - ecosystems: Optional ecosystem filter
//   - excludePaths: Optional directory globs to skip during filesystem walks
//
// For Git repository snapshots, output echoes ref, effectiveRef, and commit
// when Deputy's target resolver provides that metadata.
//
// ## analyze_dependency_graph
//
// Builds and analyzes the dependency graph to understand how vulnerabilities
// are introduced. Can find paths from direct dependencies to any vulnerable
// transitive dependency.
//
// Input:
//   - path: Path to the directory (required)
//   - targetPurl: Optional PURL to find paths to
//   - ref: Optional Git reference, branch, tag, or commit for repository paths
//   - ecosystems: Optional ecosystem filter
//   - excludePaths: Optional directory globs to skip during filesystem walks
//   - resolveTransitives: If true, use package registry, deps.dev, and Git
//     lookups for more precise transitive edges; default false uses local
//     files only
//   - extended: If true, include extended graph metadata where supported, such
//     as Go import status for required and declared modules
//
// When targetPurl is provided, output includes target.found, target.pathCount,
// matched target PURLs and nodes, and a message so agents can distinguish
// absent packages from packages that are present but disconnected/pathless.
// vulnerablePaths is capped at 50 returned examples; use vulnerablePathCount
// and vulnerablePathsTruncated to detect sampling. pathsToTarget is capped at
// 20 returned examples; use target.pathCount and pathsToTargetTruncated for the
// full target-path count. For Git repository snapshots, output echoes ref,
// effectiveRef, and commit so results can be correlated with scans of the same
// snapshot.
//
// ## graph_why
//
// Shows why a package is in the dependency graph by tracing dependency paths
// from direct dependencies to the target package. Similar to 'go mod why' but
// works across all ecosystems.
//
// Input:
//   - path: Path to the directory (required)
//   - package: Package name, name@version, or PURL to trace
//   - ref: Optional Git reference, branch, tag, or commit for repository paths
//   - showAll: Return up to 100 path examples instead of the default 10
//   - ecosystems: Optional ecosystem filter
//   - excludePaths: Optional directory globs to skip during filesystem walks
//   - resolveTransitives: If true, use package registry, deps.dev, and Git
//     lookups for more precise transitive edges; default false uses local
//     files only
//   - extended: If true, include extended graph metadata where supported, such
//     as Go import status for required and declared modules
//
// Output includes matchedNode even when no dependency path is found, so agents
// can inspect the matched package's PURL, directness, depth, disconnected
// status, and import status before choosing the next remediation step.
// paths is capped at 10 returned examples by default or 100 when showAll=true;
// use pathCount and pathsTruncated to detect sampling. For Git repository
// snapshots, output echoes ref, effectiveRef, and commit.
//
// ## graph_needs
//
// Shows what packages depend on a given package (reverse dependency lookup).
// Useful for understanding the impact of upgrading or removing a dependency.
//
// Input:
//   - path: Path to the directory (required)
//   - package: Package name, name@version, or PURL to find dependents of
//   - ref: Optional Git reference, branch, tag, or commit for repository paths
//   - ecosystems: Optional ecosystem filter
//   - excludePaths: Optional directory globs to skip during filesystem walks
//   - resolveTransitives: If true, use package registry, deps.dev, and Git
//     lookups for more precise transitive edges; default false uses local
//     files only
//   - extended: If true, include extended graph metadata where supported, such
//     as Go import status for required and declared modules
//
// Output includes matchedNode (as in graph_why) so agents can inspect the
// matched package's PURL, directness, depth, and import status even when the
// dependents list is empty (for example a direct/root dependency). For Git
// repository snapshots, output echoes ref, effectiveRef, and commit.
//
// ## triage_vulnerabilities
//
// Prioritizes and summarizes vulnerabilities by severity, exploitability, and
// fixability to help focus remediation efforts. Returns recommendations for
// addressing the most critical issues. Direct/transitive fixable counts are
// reported separately so agents do not confuse a direct unfixable finding with
// a transitive fixable one. Unknown severity findings are counted explicitly so
// severity totals add up to the overall vulnerability count.
//
// Input:
//   - path: Path to the directory (required)
//   - ref: Optional Git reference, branch, tag, or commit for repository paths
//   - ecosystems: Optional ecosystem filter
//   - excludePaths: Optional directory globs to skip during filesystem walks
//
// Output:
//   - vulnerabilities[].purl: Package URL for exact follow-up with graph_why,
//     graph_needs, or scan_package when available
//   - ref/effectiveRef/commit echo Git snapshot identity when available
//
// ## diff_refs
//
// Compares dependencies between Git references (branches, tags, commits) or
// container images. Shows added, removed, and updated packages along with
// vulnerability analysis.
//
// Input:
//   - path: Path to repository (required for Git refs; omit for container diff)
//   - baseRef: Base Git reference or container image
//   - targetRef: Target Git reference or container image to compare against
//   - platform: Optional platform for container image diffs
//   - ecosystems: Optional ecosystem filter (for Git diffs)
//   - excludePaths: Optional directory globs to skip during Git ref scans
//
// baseRef and targetRef must be the same kind: either both Git refs or both
// container image refs. Common branch names such as main and HEAD are treated
// as Git refs and require path. Dependency changes are sorted with direct
// packages first, then by change type, ecosystem, package name, PURL, and
// versions for stable repeated agent calls.
package mcp
