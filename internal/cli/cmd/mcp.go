package cmd

import (
	"fmt"

	"github.com/temporalio/deputy/internal/mcp"
	"github.com/spf13/cobra"
)

// AddMCPCommand adds the mcp command and its subcommands to the root command.
func AddMCPCommand(root *cobra.Command) {
	mcpCmd := &cobra.Command{
		Use:   "mcp",
		Short: "Model Context Protocol server for AI assistants",
		Long: `Run an MCP (Model Context Protocol) server to expose Deputy's
vulnerability analysis capabilities to AI assistants like Claude.

The MCP server provides tools for:
  - Explaining vulnerabilities by ID (CVE, GHSA)
  - Scanning packages for known vulnerabilities
  - Batch vulnerability lookups
  - Directory and container scanning
  - SBOM generation
  - Dependency graph analysis
  - Vulnerability triage and remediation`,
	}

	var (
		transport string
		address   string
	)

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the MCP server",
		Long: `Start the Deputy MCP server.

The server exposes Deputy's vulnerability analysis tools to MCP-compatible
AI assistants. It supports two transport modes:

STDIO TRANSPORT (default):
  Communicates over stdin/stdout using JSON-RPC. Best for local integrations
  with Claude Desktop, Claude Code, Cursor, VS Code, and other desktop tools.

HTTP TRANSPORT (SSE):
  Runs an HTTP server using Server-Sent Events (SSE) for communication.
  Best for remote access, shared servers, or containerized deployments.
  Includes /health and /info endpoints for monitoring.

QUICK SETUP:

  Claude Code:    claude mcp add --transport stdio deputy -- deputy mcp serve
  Codex CLI:      codex mcp add deputy -- deputy mcp serve
  VS Code:        Run "MCP: Add Server" from Command Palette
  Cursor:         Add to .cursor/mcp.json (see docs)

CLAUDE DESKTOP (~/.config/Claude/claude_desktop_config.json):

  {
    "mcpServers": {
      "deputy": {
        "command": "deputy",
        "args": ["mcp", "serve"]
      }
    }
  }

CODEX (~/.codex/config.toml):

  [mcp_servers.deputy]
  command = "deputy"
  args = ["mcp", "serve"]

Full documentation: https://github.com/temporalio/deputy/blob/main/docs/commands/mcp.md`,
		Example: `  # Start MCP server with stdio transport (default)
  deputy mcp serve

  # Start MCP server with HTTP transport on port 8080
  deputy mcp serve --transport http --address :8080

  # Start HTTP server on specific interface
  deputy mcp serve --transport http --address 127.0.0.1:9000

  # Check server health (HTTP mode)
  curl http://localhost:8080/health

  # Get server info (HTTP mode)
  curl http://localhost:8080/info`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			server := mcp.NewServer()

			switch transport {
			case "stdio":
				return server.Run(cmd.Context())
			case "http", "sse":
				if address == "" {
					address = ":8080"
				}
				return server.RunHTTP(cmd.Context(), address)
			default:
				return fmt.Errorf("unsupported transport %q: must be stdio or http", transport)
			}
		},
	}

	serveCmd.Flags().StringVar(&transport, "transport", "stdio", "Transport mode: stdio (default) or http")
	serveCmd.Flags().StringVar(&address, "address", "", "Address to listen on for HTTP transport (e.g., :8080, 127.0.0.1:9000)")

	mcpCmd.AddCommand(serveCmd)
	root.AddCommand(mcpCmd)
}
