// Package mcp provides a Model Context Protocol server for Deputy.
//
// The MCP server exposes Deputy's dependency analysis and vulnerability scanning
// capabilities to AI assistants and other tools that support the MCP protocol.
//
// # Available Tools
//
// The server provides the following tools:
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
// ## scan_directory
//
// Scans a local directory for vulnerabilities by analyzing dependency manifests
// (go.mod, package.json, requirements.txt, etc.). Returns vulnerability counts
// by severity and detailed information about each finding.
//
// Input:
//   - path: Path to the directory to scan (required)
//   - ecosystems: Optional list of ecosystems to scan (e.g., ["go", "npm"])
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
//   - direct_only: If true, only return direct dependencies
//   - ecosystems: Optional ecosystem filter
//
// ## generate_sbom
//
// Generates a Software Bill of Materials for a directory or repository.
// Supports CycloneDX, SPDX, and Protobom JSON formats.
//
// Input:
//   - path: Path to the directory or repository (required)
//   - ref: Git reference (branch, tag, commit). Defaults to HEAD.
//   - format: Output format (cyclonedx-json, spdx-json, protobom-json)
//   - enrich_licenses: Enable license enrichment from deps.dev
//
// ## get_remediation
//
// Analyzes vulnerabilities and provides remediation commands. For each
// vulnerable dependency with a known fix, returns the appropriate package
// manager command to upgrade.
//
// Input:
//   - path: Path to the directory (required)
//   - ecosystems: Optional ecosystem filter
//
// ## analyze_dependency_graph
//
// Builds and analyzes the dependency graph to understand how vulnerabilities
// are introduced. Can find paths from direct dependencies to any vulnerable
// transitive dependency.
//
// Input:
//   - path: Path to the directory (required)
//   - target_purl: Optional PURL to find paths to
//   - ecosystems: Optional ecosystem filter
//
// ## graph_why
//
// Shows why a package is in the dependency graph by tracing dependency paths
// from direct dependencies to the target package. Similar to 'go mod why' but
// works across all ecosystems.
//
// Input:
//   - path: Path to the directory (required)
//   - package: Package name to trace (e.g., "lodash", "golang.org/x/crypto")
//   - show_all: Show all paths, not just shortest (default: false)
//   - ecosystems: Optional ecosystem filter
//
// ## graph_needs
//
// Shows what packages depend on a given package (reverse dependency lookup).
// Useful for understanding the impact of upgrading or removing a dependency.
//
// Input:
//   - path: Path to the directory (required)
//   - package: Package name to find dependents of
//   - ecosystems: Optional ecosystem filter
//
// ## triage_vulnerabilities
//
// Prioritizes and summarizes vulnerabilities by severity, exploitability, and
// fixability to help focus remediation efforts. Returns recommendations for
// addressing the most critical issues.
//
// Input:
//   - path: Path to the directory (required)
//   - ecosystems: Optional ecosystem filter
//
// ## diff_refs
//
// Compares dependencies between Git references (branches, tags, commits) or
// container images. Shows added, removed, and updated packages along with
// vulnerability analysis.
//
// Input:
//   - path: Path to repository (required for Git refs, optional for container diff)
//   - base_ref: Base Git reference or container image
//   - target_ref: Target Git reference or container image to compare against
//   - ecosystems: Optional ecosystem filter (for Git diffs)
package mcp
