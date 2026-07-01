package cmd

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/temporalio/deputy/internal/auth/jwt"
	"github.com/temporalio/deputy/internal/mcp"
)

type mcpServeFlags struct {
	transport string
	address   string

	authMode           string
	authJWKSURL        string
	authOIDCDiscovery  bool
	authIssuers        []string
	authAudiences      []string
	authRequiredClaims []string
	authClockSkew      time.Duration
	allowInsecure      bool
}

// AddMCPCommand adds the mcp command and its subcommands to the root command.
func AddMCPCommand(root *cobra.Command) {
	mcpCmd := &cobra.Command{
		Use:   "mcp",
		Short: "Model Context Protocol server for AI assistants",
		Long: `Run an MCP (Model Context Protocol) server to expose Deputy's
vulnerability analysis capabilities to AI assistants like Claude and Codex.

The MCP server provides tools for:
  - Explaining vulnerabilities by ID (CVE, GHSA)
  - Scanning packages for known vulnerabilities
  - Batch vulnerability lookups
  - Directory and container scanning
  - SBOM generation
  - Dependency graph analysis
  - Vulnerability triage and remediation`,
	}

	flags := &mcpServeFlags{}

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
  Use --auth-mode required with --auth-jwks-url for shared HTTP deployments.

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

  # Start local MCP HTTP server on port 8080
  deputy mcp serve --transport http

  # Start HTTP server on specific interface
  deputy mcp serve --transport http --address 127.0.0.1:9000

  # Start public HTTP server with required JWT auth
  deputy mcp serve --transport http --address 0.0.0.0:8080 \
    --auth-mode required --auth-jwks-url https://issuer.example.com/.well-known/jwks.json

  # Check server health (HTTP mode)
  curl http://localhost:8080/health

  # Get server info (HTTP mode)
  curl http://localhost:8080/info`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			server := mcp.NewServer(mcp.WithDefaultExcludePaths(discoverConfigExcludePaths()))

			switch flags.transport {
			case "stdio":
				if flags.hasAuthSettings() {
					return fmt.Errorf("MCP HTTP auth/exposure flags require --transport http")
				}
				return server.Run(cmd.Context())
			case "http", "sse":
				if flags.address == "" {
					flags.address = "127.0.0.1:8080"
				}
				cfg, err := mcpHTTPConfigFromFlags(*flags)
				if err != nil {
					return err
				}
				if err := validateMCPHTTPExposure(flags.address, cfg, flags.allowInsecure); err != nil {
					return err
				}
				return server.RunHTTPWithConfig(cmd.Context(), flags.address, cfg)
			default:
				return fmt.Errorf("unsupported transport %q: must be stdio or http", flags.transport)
			}
		},
	}

	serveCmd.Flags().StringVar(&flags.transport, "transport", "stdio", "Transport mode: stdio (default) or http")
	serveCmd.Flags().StringVar(&flags.address, "address", "127.0.0.1:8080", "Address to listen on for HTTP transport (e.g., 127.0.0.1:8080, 0.0.0.0:8080)")
	serveCmd.Flags().StringVar(&flags.authMode, "auth-mode", "disabled", "HTTP authentication mode: disabled, optional, or required")
	serveCmd.Flags().StringVar(&flags.authJWKSURL, "auth-jwks-url", "", "JWKS endpoint URL or OIDC issuer URL for HTTP JWT validation")
	serveCmd.Flags().BoolVar(&flags.authOIDCDiscovery, "auth-oidc-discovery", false, "Use OIDC discovery to resolve JWKS from the issuer URL")
	serveCmd.Flags().StringSliceVar(&flags.authIssuers, "auth-issuers", nil, "Trusted JWT issuers for HTTP auth (comma-separated)")
	serveCmd.Flags().StringSliceVar(&flags.authAudiences, "auth-audiences", nil, "Expected JWT audiences for HTTP auth (comma-separated)")
	serveCmd.Flags().StringSliceVar(&flags.authRequiredClaims, "auth-required-claims", nil, "Required JWT claims for HTTP auth (comma-separated)")
	serveCmd.Flags().DurationVar(&flags.authClockSkew, "auth-clock-skew", 0, "Clock skew tolerance for HTTP token validation (max 5m)")
	serveCmd.Flags().BoolVar(&flags.allowInsecure, "allow-insecure", false, "Allow unauthenticated MCP HTTP on non-loopback addresses")

	mcpCmd.AddCommand(serveCmd)
	root.AddCommand(mcpCmd)
}

func mcpHTTPConfigFromFlags(flags mcpServeFlags) (mcp.HTTPConfig, error) {
	cfg := mcp.DefaultHTTPConfig()
	mode := strings.ToLower(strings.TrimSpace(flags.authMode))
	if mode == "" {
		mode = "disabled"
	}

	switch mode {
	case "disabled":
		if flags.hasAuthDetails() {
			return cfg, fmt.Errorf("MCP HTTP auth details require --auth-mode optional or --auth-mode required")
		}
		return cfg, nil
	case "optional", "required":
	default:
		return cfg, fmt.Errorf("unsupported MCP auth mode %q: must be disabled, optional, or required", flags.authMode)
	}

	if strings.TrimSpace(flags.authJWKSURL) == "" {
		return cfg, fmt.Errorf("MCP HTTP auth mode %q requires --auth-jwks-url", mode)
	}
	if flags.authClockSkew < 0 {
		return cfg, fmt.Errorf("MCP HTTP auth clock skew must be non-negative")
	}
	if flags.authClockSkew > jwt.MaxClockSkew {
		return cfg, fmt.Errorf("MCP HTTP auth clock skew %v exceeds maximum allowed %v", flags.authClockSkew, jwt.MaxClockSkew)
	}

	cfg.Auth = &mcp.AuthConfig{
		Mode:           mode,
		Issuers:        trimStringSlice(flags.authIssuers),
		Audiences:      trimStringSlice(flags.authAudiences),
		RequiredClaims: trimStringSlice(flags.authRequiredClaims),
		ClockSkew:      flags.authClockSkew,
		JWKS: &mcp.JWKSConfig{
			URL:           strings.TrimSpace(flags.authJWKSURL),
			OIDCDiscovery: flags.authOIDCDiscovery,
		},
	}
	return cfg, nil
}

func validateMCPHTTPExposure(address string, cfg mcp.HTTPConfig, allowInsecure bool) error {
	if allowInsecure || isLoopbackAddress(address) {
		return nil
	}
	mode := "disabled"
	if cfg.Auth != nil && cfg.Auth.Mode != "" {
		mode = string(cfg.Auth.Mode)
	}
	if mode == "required" {
		return nil
	}
	return fmt.Errorf("MCP HTTP address %q is not loopback; use --auth-mode required with JWT auth or pass --allow-insecure intentionally", address)
}

func isLoopbackAddress(address string) bool {
	host := strings.TrimSpace(address)
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (f mcpServeFlags) hasAuthDetails() bool {
	return strings.TrimSpace(f.authJWKSURL) != "" ||
		f.authOIDCDiscovery ||
		len(f.authIssuers) > 0 ||
		len(f.authAudiences) > 0 ||
		len(f.authRequiredClaims) > 0 ||
		f.authClockSkew != 0
}

func (f mcpServeFlags) hasAuthSettings() bool {
	mode := strings.ToLower(strings.TrimSpace(f.authMode))
	return (mode != "" && mode != "disabled") || f.hasAuthDetails() || f.allowInsecure
}

func trimStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value != "" {
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
