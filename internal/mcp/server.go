package mcp

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	packageurl "github.com/package-url/packageurl-go"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	graphv1 "github.com/temporalio/deputy/gen/deputy/graph/v1"
	listv1 "github.com/temporalio/deputy/gen/deputy/list/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/cli/flags"
	"github.com/temporalio/deputy/internal/dependency/graph"
	"github.com/temporalio/deputy/internal/dependency/graphquery"
	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/logs"
	"github.com/temporalio/deputy/internal/otel"
	"github.com/temporalio/deputy/internal/policy"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/purlx"
	"github.com/temporalio/deputy/internal/remediation"
	sbomx "github.com/temporalio/deputy/internal/sbom"
	"github.com/temporalio/deputy/internal/services"
	"github.com/temporalio/deputy/internal/version"
	"github.com/temporalio/deputy/internal/vulnerability"
	vulnseverity "github.com/temporalio/deputy/internal/vulnerability/severity"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/mod/semver"
)

// ToolTimeouts configures timeouts for different categories of tool operations.
type ToolTimeouts struct {
	// Default is the timeout for quick operations like vulnerability lookups.
	// Default: 30 seconds.
	Default time.Duration

	// Scan is the timeout for scanning operations (directories, containers).
	// Default: 5 minutes.
	Scan time.Duration

	// Graph is the timeout for dependency graph analysis.
	// Default: 2 minutes.
	Graph time.Duration

	// SBOM is the timeout for SBOM generation.
	// Default: 3 minutes.
	SBOM time.Duration
}

// DefaultToolTimeouts returns sensible default timeouts for tool operations.
func DefaultToolTimeouts() ToolTimeouts {
	return ToolTimeouts{
		Default: 30 * time.Second,
		Scan:    5 * time.Minute,
		Graph:   2 * time.Minute,
		SBOM:    3 * time.Minute,
	}
}

// Server wraps the MCP server with Deputy-specific tools.
type Server struct {
	server              *mcp.Server
	clients             *services.Clients
	toolNames           []string     // registered tool names for /info endpoint
	toolTimeouts        ToolTimeouts // configurable timeouts for tool operations
	defaultExcludePaths []string
	startedAt           time.Time
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithClients configures custom clients for the server.
func WithClients(c *services.Clients) ServerOption {
	return func(s *Server) {
		s.clients = c
	}
}

// WithToolTimeouts configures custom timeouts for tool operations.
func WithToolTimeouts(timeouts ToolTimeouts) ServerOption {
	return func(s *Server) {
		s.toolTimeouts = timeouts
	}
}

// WithDefaultExcludePaths configures directory-glob exclusions applied to every
// local source scan. Per-tool excludePaths are merged with these defaults.
func WithDefaultExcludePaths(paths []string) ServerOption {
	return func(s *Server) {
		s.defaultExcludePaths = normalizeMCPExcludePaths(paths)
	}
}

// WithServices uses services.Services to create in-process clients.
// This is the recommended way to configure the MCP server.
//
// Example:
//
//	svc, _ := services.New()
//	server := mcp.NewServer(mcp.WithServices(svc))
func WithServices(svc *services.Services) ServerOption {
	return func(s *Server) {
		s.clients = svc.InProcessClients()
	}
}

// serverInstructions is sent to clients in the MCP initialize response. It
// orients an agent to Deputy's model and how the tools compose; it deliberately
// does not restate per-tool inputs (the tool schemas cover those). Keep it
// concise — it is injected into the client's context once per session.
const serverInstructions = "Deputy is a supply-chain security engine. Its tools scan dependencies and container images against known-vulnerability data (OSV: CVE/GHSA/Go vuln DB), explain and prioritize findings, trace dependency graphs, generate SBOMs, and propose remediation. Every tool is read-only and safe to call repeatedly; tools that reach the network are annotated with openWorldHint.\n" +
	"\n" +
	"Targets\n" +
	"- Directory tools take a local `path` plus an optional `ref` (branch, tag, or commit) to analyze a specific Git snapshot. Results echo the resolved `effectiveRef`/`commit` so you can confirm exactly what was analyzed.\n" +
	"- `scan_container` takes an image reference; `scan_package` checks a single package.\n" +
	"\n" +
	"Package identity\n" +
	"- Prefer a PURL (e.g. `pkg:npm/lodash@4.17.21`) for exact matches. Tools also accept `name`, `name@version`, or `name` + `ecosystem`. Ecosystem names are lenient (e.g. `gha` resolves to `github-actions`, `golang` to `go`).\n" +
	"\n" +
	"Reading results\n" +
	"- Severity totals include an `unknown` bucket, so per-severity counts always sum to the total.\n" +
	"- List-like outputs are capped and set a `*Truncated` flag alongside a full count (e.g. `pathCount` with `pathsTruncated`); check them before assuming a result is complete. Ordering is deterministic across calls.\n" +
	"- A clean target reports `clean: true` with an empty findings list — this is success, not an error.\n" +
	"- A package absent from the graph is a normal `found: false` result (with a `matchedNode` when the package is present but has no paths), not an error.\n" +
	"\n" +
	"Typical workflow\n" +
	"- Assess: `scan_directory` then `triage_vulnerabilities` to rank findings by severity and fixability.\n" +
	"- Investigate: `graph_why` (why a package is present) and `graph_needs` (what depends on it). Set `resolveTransitives` for precise transitive edges (slower, may use the network).\n" +
	"- Remediate: `get_remediation` for upgrade/migration commands; hints reference these MCP tools by name.\n" +
	"- Compare: `diff_refs` for two Git refs or two container images.\n" +
	"- Author policies: `list_policy_entrypoints` returns entrypoints, categories, CEL variables, and helpers."

// NewServer creates a new Deputy MCP server with vulnerability analysis tools.
func NewServer(opts ...ServerOption) *Server {
	impl := &mcp.Implementation{
		Name:    "deputy",
		Version: version.Value,
	}

	server := mcp.NewServer(impl, &mcp.ServerOptions{Instructions: serverInstructions})
	s := &Server{
		server:       server,
		toolTimeouts: DefaultToolTimeouts(),
		startedAt:    time.Now().UTC(),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Create default clients if not provided.
	if s.clients == nil {
		svc, err := services.New()
		if err != nil {
			// Surface the failure rather than swallowing it: with empty clients
			// tool calls will error (or panic under recovery) on first use, and
			// a silent construction would make that hard to diagnose.
			logs.Error(context.Background(), "MCP server failed to initialize services", "error", err)
			s.clients = &services.Clients{}
		} else {
			s.clients = svc.InProcessClients()
		}
	}

	s.registerTools()
	return s
}

// Run starts the MCP server over stdio transport.
func (s *Server) Run(ctx context.Context) error {
	return s.server.Run(ctx, &mcp.StdioTransport{})
}

// HTTPConfig configures the HTTP server for MCP.
type HTTPConfig struct {
	// ReadTimeout is the maximum duration for reading the entire request.
	// Default: 30 seconds.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out writes of the response.
	// For SSE, this should be long enough to maintain connections.
	// Default: 0 (no timeout, required for SSE long-polling).
	WriteTimeout time.Duration

	// IdleTimeout is the maximum time to wait for the next request when keep-alives are enabled.
	// Default: 120 seconds.
	IdleTimeout time.Duration

	// ReadHeaderTimeout is the time allowed to read request headers.
	// Default: 10 seconds.
	ReadHeaderTimeout time.Duration

	// MaxHeaderBytes controls the maximum number of bytes the server will
	// read parsing the request header's keys and values.
	// Default: 1MB.
	MaxHeaderBytes int

	// ShutdownTimeout is the maximum time to wait for active connections to close
	// during graceful shutdown.
	// Default: 30 seconds.
	ShutdownTimeout time.Duration

	// Auth configures JWT authentication for the HTTP server.
	// If nil or Mode is "disabled", authentication is disabled (default).
	Auth *AuthConfig
}

// DefaultHTTPConfig returns the default HTTP configuration for production use.
func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // SSE requires no write timeout for long-polling
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
		ShutdownTimeout:   30 * time.Second,
	}
}

// RunHTTP starts the MCP server over HTTP (SSE) transport with default configuration.
// The server listens on the specified address and serves MCP sessions
// via Server-Sent Events (SSE) as defined by the MCP specification.
//
// Clients initiate sessions via GET requests (which establish SSE streams)
// and send messages via POST requests to session endpoints.
func (s *Server) RunHTTP(ctx context.Context, addr string) error {
	return s.RunHTTPWithConfig(ctx, addr, DefaultHTTPConfig())
}

// RunHTTPWithConfig starts the MCP server over HTTP (SSE) transport with custom configuration.
func (s *Server) RunHTTPWithConfig(ctx context.Context, addr string, cfg HTTPConfig) error {
	authMode := "disabled"
	if cfg.Auth != nil && cfg.Auth.Mode != "" {
		authMode = cfg.Auth.Mode
	}

	logs.Info(ctx, "Starting MCP HTTP server",
		"address", addr,
		"read_timeout", cfg.ReadTimeout,
		"idle_timeout", cfg.IdleTimeout,
		"auth_mode", authMode,
	)

	// Set up authentication middleware
	authMw, authClose, err := authMiddleware(cfg.Auth)
	if err != nil {
		return fmt.Errorf("create auth middleware: %w", err)
	}
	defer authClose()

	// Get base handler and wrap with auth middleware
	handler := authMw(s.HTTPHandler())

	// Create HTTP server with production-grade configuration
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}

	// Handle graceful shutdown
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logs.Info(ctx, "Shutting down MCP HTTP server")
		shutdownTimeout := cfg.ShutdownTimeout
		if shutdownTimeout == 0 {
			shutdownTimeout = 30 * time.Second
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

// HTTPHandler returns an http.Handler that serves MCP over SSE.
// This can be mounted on an existing HTTP server or mux.
//
// The handler serves both the SSE endpoint (GET) for establishing sessions
// and the message endpoint (POST) for client-to-server messages.
//
// The handler includes panic recovery middleware that logs panics and returns
// a 500 Internal Server Error response instead of crashing the server.
func (s *Server) HTTPHandler() http.Handler {
	mux := http.NewServeMux()

	// SSE handler for MCP sessions
	sseHandler := mcp.NewSSEHandler(func(req *http.Request) *mcp.Server {
		return s.server
	}, nil)

	// Health check endpoint
	mux.HandleFunc("/health", s.handleHealth)

	// Version/info endpoint
	mux.HandleFunc("/info", s.handleInfo)

	// MCP SSE endpoint - handle both root and /mcp paths
	mux.Handle("/", sseHandler)
	mux.Handle("/mcp", sseHandler)

	// Wrap with panic recovery middleware
	return s.panicRecoveryMiddleware(mux)
}

// panicRecoveryMiddleware wraps an http.Handler with panic recovery.
// It logs panics with full context and returns a 500 error to the client.
func (s *Server) panicRecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// Log the panic with context
				logs.Error(r.Context(), "Panic recovered in HTTP handler",
					"panic", rec,
					"method", r.Method,
					"path", r.URL.Path,
					"remote_addr", r.RemoteAddr,
				)

				// Return 500 error to client
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{
					"error":   "internal_server_error",
					"message": "An unexpected error occurred",
				})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// handleHealth serves a simple health check endpoint.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "deputy-mcp",
		"version": version.Value,
	})
}

// handleInfo serves server information.
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	info := s.serverInfo()
	info.Transport = "sse"
	json.NewEncoder(w).Encode(info)
}

// addTool is a helper that registers a tool and tracks its name for /info endpoint.
func addTool[T, R any](s *Server, tool *mcp.Tool, handler func(context.Context, *mcp.CallToolRequest, T) (*mcp.CallToolResult, R, error)) {
	mcp.AddTool(s.server, tool, handler)
	s.toolNames = append(s.toolNames, tool.Name)
}

func addReadOnlyTool[T, R any](
	s *Server,
	tool *mcp.Tool,
	openWorld bool,
	handler func(context.Context, *mcp.CallToolRequest, T) (*mcp.CallToolResult, R, error),
) {
	tool.Annotations = readOnlyToolAnnotations(openWorld)
	addTool(s, tool, handler)
}

func readOnlyToolAnnotations(openWorld bool) *mcp.ToolAnnotations {
	destructive := false
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: &destructive,
		OpenWorldHint:   &openWorld,
	}
}

// registerTools adds all Deputy tools to the MCP server.
func (s *Server) registerTools() {
	const (
		closedWorld = false
		openWorld   = true
	)

	// Server metadata
	addReadOnlyTool(s, &mcp.Tool{
		Name:        "get_server_info",
		Description: "Get Deputy MCP server build, process, and tool metadata",
		InputSchema: emptyObjectInputSchema(),
	}, closedWorld, s.getServerInfo)

	// Policy discovery tools
	addReadOnlyTool(s, &mcp.Tool{
		Name:        "list_policy_entrypoints",
		Description: "List Deputy policy entrypoints, categories, variables, and helpers for authoring CEL policies",
		InputSchema: listPolicyEntrypointsInputSchema(),
	}, closedWorld, s.listPolicyEntrypoints)

	// Vulnerability explanation tools
	addReadOnlyTool(s, &mcp.Tool{
		Name:        "explain_vulnerability",
		Description: "Get detailed information about a vulnerability by its ID (CVE, GHSA, etc.)",
		InputSchema: explainVulnerabilityInputSchema(),
	}, openWorld, s.explainVulnerability)

	addReadOnlyTool(s, &mcp.Tool{
		Name:        "explain_vulnerabilities",
		Description: "Get detailed information about multiple vulnerabilities by their IDs",
		InputSchema: explainVulnerabilitiesInputSchema(),
	}, openWorld, s.explainVulnerabilities)

	// Package scanning tools
	addReadOnlyTool(s, &mcp.Tool{
		Name:        "scan_package",
		Description: "Check a single package for known vulnerabilities by PURL or by name, version, and ecosystem",
		InputSchema: scanPackageInputSchema(),
	}, openWorld, s.scanPackage)

	addReadOnlyTool(s, &mcp.Tool{
		Name:        "scan_directory",
		Description: "Scan a local directory for vulnerabilities by analyzing dependency manifests (go.mod, package.json, etc.)",
		InputSchema: scanDirectoryInputSchema(),
	}, openWorld, s.scanDirectory)

	// Dependency tools
	addReadOnlyTool(s, &mcp.Tool{
		Name:        "list_dependencies",
		Description: "List all dependencies in a directory, optionally filtering to direct dependencies only",
		InputSchema: listDependenciesInputSchema(),
	}, closedWorld, s.listDependencies)

	// SBOM tools
	addReadOnlyTool(s, &mcp.Tool{
		Name:        "generate_sbom",
		Description: "Generate a Software Bill of Materials (SBOM) for a local directory or repository checkout",
		InputSchema: generateSBOMInputSchema(),
	}, openWorld, s.generateSBOM)

	// Remediation tools
	addReadOnlyTool(s, &mcp.Tool{
		Name:        "get_remediation",
		Description: "Get remediation commands for fixing vulnerabilities in a scanned directory",
		InputSchema: getRemediationInputSchema(),
	}, openWorld, s.getRemediation)

	// Graph analysis tools
	addReadOnlyTool(s, &mcp.Tool{
		Name:        "analyze_dependency_graph",
		Description: "Build dependency graph stats and optionally find paths to a package PURL",
		InputSchema: analyzeGraphInputSchema(),
	}, openWorld, s.analyzeDependencyGraph)

	addReadOnlyTool(s, &mcp.Tool{
		Name:        "graph_why",
		Description: "Show why a package name, name@version, or PURL is in the dependency graph",
		InputSchema: graphWhyInputSchema(),
	}, openWorld, s.graphWhy)

	addReadOnlyTool(s, &mcp.Tool{
		Name:        "graph_needs",
		Description: "Show what packages depend on a package name, name@version, or PURL",
		InputSchema: graphNeedsInputSchema(),
	}, openWorld, s.graphNeeds)

	// Triage tools
	addReadOnlyTool(s, &mcp.Tool{
		Name:        "triage_vulnerabilities",
		Description: "Prioritize and summarize vulnerabilities by severity, exploitability, and fixability to help focus remediation efforts",
		InputSchema: triageInputSchema(),
	}, openWorld, s.triageVulnerabilities)

	// Container scanning tools
	addReadOnlyTool(s, &mcp.Tool{
		Name:        "scan_container",
		Description: "Scan a container image for vulnerabilities. Supports remote registries (nginx:1.25, ghcr.io/owner/app:v1) and local Docker daemon images (docker-daemon://myapp:latest).",
		InputSchema: scanContainerInputSchema(),
	}, openWorld, s.scanContainer)

	// Diff tools
	addReadOnlyTool(s, &mcp.Tool{
		Name:        "diff_refs",
		Description: "Compare dependencies between Git references (branches, tags, commits) or container images. Shows added, removed, and updated packages with vulnerability analysis.",
		InputSchema: diffRefsInputSchema(),
	}, openWorld, s.diffRefs)
}

func mcpStringProperty(description string) *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Description: description,
		MinLength:   jsonschema.Ptr(1),
		Pattern:     "\\S",
	}
}

func mcpOptionalStringProperty(description string) *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Description: description,
	}
}

func mcpStringArrayProperty(description string) *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "array",
		Description: description,
		Items:       mcpStringProperty("Non-empty string value."),
	}
}

func explainVulnerabilityInputSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:     "object",
		Required: []string{"id"},
		Properties: map[string]*jsonschema.Schema{
			"id": mcpStringProperty("Vulnerability ID, e.g. CVE-2021-44228 or GHSA-xxxx-xxxx-xxxx."),
			"referenceLimit": {
				Type:        "integer",
				Description: "Optional maximum number of advisory references to return. Omit or pass a negative value for all references; 0 returns none.",
			},
		},
		AdditionalProperties: falseJSONSchema(),
	}
}

func emptyObjectInputSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:                 "object",
		AdditionalProperties: falseJSONSchema(),
	}
}

func explainVulnerabilitiesInputSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:     "object",
		Required: []string{"ids"},
		Properties: map[string]*jsonschema.Schema{
			"ids": {
				Type:        "array",
				Description: "Vulnerability IDs to explain, e.g. CVE-2021-44228 or GHSA-xxxx-xxxx-xxxx.",
				Items:       mcpStringProperty("Vulnerability ID."),
				MinItems:    jsonschema.Ptr(1),
			},
			"referenceLimit": {
				Type:        "integer",
				Description: "Optional maximum number of advisory references to return per vulnerability. Omit or pass a negative value for all references; 0 returns none.",
			},
		},
		AdditionalProperties: falseJSONSchema(),
	}
}

func listPolicyEntrypointsInputSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"category": {
				Type:        "string",
				Description: "Optional category filter: scan, proxy, diff, container_diff, sbom, fix, triage, dockerfile, secrets, graph, server, or sandbox. Legacy aliases container, service, and exec are accepted.",
				Enum:        []any{"scan", "proxy", "diff", "container_diff", "container", "sbom", "fix", "triage", "dockerfile", "secrets", "graph", "server", "service", "sandbox", "exec"},
			},
		},
		AdditionalProperties: falseJSONSchema(),
	}
}

func scanPackageInputSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"purl":      mcpStringProperty("Package URL, e.g. pkg:npm/lodash@4.17.21. Include @version in the PURL or provide version separately."),
			"name":      mcpStringProperty("Package name (e.g., lodash, github.com/foo/bar), Maven coordinates (group:artifact), or a pkg: PURL."),
			"version":   mcpStringProperty("Package version. Required unless purl or name includes a pkg: PURL with @version."),
			"ecosystem": mcpStringProperty("Package ecosystem (e.g., npm, go, pypi, maven, cargo, github-actions). Required with split name/version input."),
		},
		AnyOf: []*jsonschema.Schema{
			{Required: []string{"purl"}},
			{Required: []string{"name", "version", "ecosystem"}},
			{
				Required: []string{"name"},
				Properties: map[string]*jsonschema.Schema{
					"name": {
						Type:      "string",
						Pattern:   "^[Pp][Kk][Gg]:",
						MinLength: jsonschema.Ptr(1),
					},
				},
			},
		},
		AdditionalProperties: falseJSONSchema(),
	}
}

func scanDirectoryInputSchema() *jsonschema.Schema {
	return localPathToolInputSchema("Path to the local directory to scan.", map[string]*jsonschema.Schema{
		"ref":          mcpOptionalStringProperty("Git reference, branch, tag, or commit for repository paths. Defaults to the current working tree/HEAD."),
		"ecosystems":   mcpStringArrayProperty("Optional ecosystems to scan, e.g. go, npm, pypi. Scans all if empty."),
		"excludePaths": mcpStringArrayProperty("Optional directory globs to skip during the walk, e.g. .bin/** or **/testdata."),
	})
}

func listDependenciesInputSchema() *jsonschema.Schema {
	return localPathToolInputSchema("Path to the local directory to analyze.", map[string]*jsonschema.Schema{
		"directOnly":   {Type: "boolean", Description: "If true, only return direct dependencies."},
		"ref":          mcpOptionalStringProperty("Git reference, branch, tag, or commit for repository paths. Defaults to the current working tree/HEAD."),
		"ecosystems":   mcpStringArrayProperty("Optional ecosystems to include, e.g. go, npm, pypi."),
		"excludePaths": mcpStringArrayProperty("Optional directory globs to skip during the walk, e.g. .bin/** or **/testdata."),
	})
}

func getRemediationInputSchema() *jsonschema.Schema {
	return localPathToolInputSchema("Path to the local directory to analyze for remediation.", map[string]*jsonschema.Schema{
		"ref":          mcpOptionalStringProperty("Git reference, branch, tag, or commit for repository paths. Defaults to the current working tree/HEAD."),
		"ecosystems":   mcpStringArrayProperty("Optional ecosystems to include, e.g. go, npm, pypi."),
		"excludePaths": mcpStringArrayProperty("Optional directory globs to skip during the walk, e.g. .bin/** or **/testdata."),
	})
}

func triageInputSchema() *jsonschema.Schema {
	return localPathToolInputSchema("Path to the local directory to analyze.", map[string]*jsonschema.Schema{
		"ref":          mcpOptionalStringProperty("Git reference, branch, tag, or commit for repository paths. Defaults to the current working tree/HEAD."),
		"ecosystems":   mcpStringArrayProperty("Optional ecosystems to include, e.g. go, npm, pypi."),
		"excludePaths": mcpStringArrayProperty("Optional directory globs to skip during the walk, e.g. .bin/** or **/testdata."),
	})
}

func analyzeGraphInputSchema() *jsonschema.Schema {
	return localPathToolInputSchema("Path to the local directory to analyze.", graphToolProperties(map[string]*jsonschema.Schema{
		"targetPurl": mcpOptionalPURLProperty("Optional package URL to find paths to, e.g. pkg:npm/lodash@4.17.21 or pkg:golang/golang.org/x/net."),
	}))
}

func graphWhyInputSchema() *jsonschema.Schema {
	return localPathToolInputSchema("Path to the local directory to analyze.", graphToolProperties(map[string]*jsonschema.Schema{
		"package": mcpStringProperty("Package name, name@version, or PURL to trace, e.g. lodash, golang.org/x/crypto@v0.17.0, or pkg:npm/lodash@4.17.21."),
		"showAll": {Type: "boolean", Description: "Return up to 100 dependency path examples instead of the default 10. Use pathCount and pathsTruncated to detect sampling."},
	}), "package")
}

func graphNeedsInputSchema() *jsonschema.Schema {
	return localPathToolInputSchema("Path to the local directory to analyze.", graphToolProperties(map[string]*jsonschema.Schema{
		"package": mcpStringProperty("Package name, name@version, or PURL to find dependents of."),
	}), "package")
}

func localPathToolInputSchema(pathDescription string, properties map[string]*jsonschema.Schema, required ...string) *jsonschema.Schema {
	props := map[string]*jsonschema.Schema{
		"path": mcpStringProperty(pathDescription),
	}
	maps.Copy(props, properties)
	return &jsonschema.Schema{
		Type:                 "object",
		Required:             append([]string{"path"}, required...),
		Properties:           props,
		AdditionalProperties: falseJSONSchema(),
	}
}

func graphToolProperties(properties map[string]*jsonschema.Schema) map[string]*jsonschema.Schema {
	properties["ref"] = mcpOptionalStringProperty("Git reference, branch, tag, or commit for repository paths. Defaults to the current working tree/HEAD.")
	properties["ecosystems"] = mcpStringArrayProperty("Optional ecosystems to include, e.g. go, npm, pypi.")
	properties["excludePaths"] = mcpStringArrayProperty("Optional directory globs to skip during the walk, e.g. .bin/** or **/testdata.")
	properties["resolveTransitives"] = &jsonschema.Schema{
		Type:        "boolean",
		Description: "If true, use package registry, deps.dev, and Git lookups to resolve more precise transitive graph edges. Slower and may require network access.",
	}
	properties["extended"] = &jsonschema.Schema{
		Type:        "boolean",
		Description: "If true, include extended graph metadata where supported, such as Go import status for required and declared modules.",
	}
	return properties
}

func mcpOptionalPURLProperty(description string) *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Description: description,
		Pattern:     "^[Pp][Kk][Gg]:\\S+",
	}
}

func scanContainerInputSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:     "object",
		Required: []string{"image"},
		Properties: map[string]*jsonschema.Schema{
			"image":    mcpStringProperty("Container image reference, e.g. nginx:1.25, ghcr.io/owner/app:v1.0.0, or docker-daemon://myapp:latest."),
			"platform": mcpOptionalStringProperty("Target platform, e.g. linux/amd64 or linux/arm64. Defaults to current platform."),
		},
		AdditionalProperties: falseJSONSchema(),
	}
}

func generateSBOMInputSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:     "object",
		Required: []string{"path"},
		Properties: map[string]*jsonschema.Schema{
			"path":           mcpStringProperty("Local directory or local repository checkout to analyze."),
			"ref":            mcpOptionalStringProperty("Git reference, branch, tag, or commit. Defaults to HEAD."),
			"format":         mcpSBOMFormatProperty(),
			"enrichLicenses": {Type: "boolean", Description: "Enrich SBOM with license information from deps.dev."},
			"ecosystems":     mcpStringArrayProperty("Optional ecosystems to include, e.g. go, npm, pypi."),
			"excludePaths":   mcpStringArrayProperty("Optional directory globs to skip during the walk, e.g. .bin/** or **/testdata."),
		},
		AdditionalProperties: falseJSONSchema(),
	}
}

func mcpSBOMFormatProperty() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:        "string",
		Description: "Output format. Defaults to cyclonedx-json. Short aliases (cyclonedx, spdx, protobom) and mixed case are also accepted.",
		Default:     jsonDefault("cyclonedx-json"),
		Enum:        []any{"cyclonedx-json", "spdx-json", "protobom-json"},
	}
}

func jsonDefault(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// mcpTargetRef extracts the requested ref, resolved effective ref, and commit
// hash from a resolved target so tool results can echo Git snapshot identity.
// All values are empty when target is nil or carries no Git metadata.
func mcpTargetRef(target *targetv1.Target) (ref, effectiveRef, commit string) {
	if target == nil {
		return "", "", ""
	}
	return strings.TrimSpace(target.GetRef()), strings.TrimSpace(target.GetEffectiveRef()), strings.TrimSpace(target.GetCommitHash())
}

func manifestRefsForMCP(refs []*dependencyv1.ManifestRef) []ManifestRefInfo {
	if len(refs) == 0 {
		return nil
	}
	out := make([]ManifestRefInfo, 0, len(refs))
	for _, ref := range refs {
		if ref == nil {
			continue
		}
		path := strings.TrimSpace(ref.GetPath())
		manager := strings.TrimSpace(ref.GetManager())
		componentKey := strings.TrimSpace(ref.GetComponentKey())
		groups := stringsForMCP(ref.GetGroups())
		if path == "" && manager == "" && componentKey == "" && len(groups) == 0 {
			continue
		}
		out = append(out, ManifestRefInfo{
			Path:         path,
			Manager:      manager,
			Groups:       groups,
			ComponentKey: componentKey,
		})
	}
	return out
}

func diffRefsInputSchema() *jsonschema.Schema {
	return &jsonschema.Schema{
		Type:     "object",
		Required: []string{"baseRef", "targetRef"},
		Properties: map[string]*jsonschema.Schema{
			"path":         mcpOptionalStringProperty("Repository path for Git ref diffs. Optional for container image diffs."),
			"baseRef":      mcpStringProperty("Base Git reference (branch, tag, commit) or container image reference."),
			"targetRef":    mcpStringProperty("Target Git reference or container image reference to compare against."),
			"platform":     mcpOptionalStringProperty("Target platform for container image diffs, e.g. linux/amd64 or linux/arm64. Ignored for Git ref diffs."),
			"ecosystems":   mcpStringArrayProperty("Optional ecosystems to include for Git ref diffs, e.g. go, npm, pypi."),
			"excludePaths": mcpStringArrayProperty("Optional directory globs to skip during Git ref scans, e.g. .bin/** or **/testdata."),
		},
		AdditionalProperties: falseJSONSchema(),
	}
}

func falseJSONSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Not: &jsonschema.Schema{}}
}

// withTimeout wraps a context with the specified timeout duration.
// Returns the new context and a cancel function that should be deferred.
// If timeout is 0, returns the original context unchanged.
func (s *Server) withTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// validateLocalPath validates a path for local filesystem access.
// It prevents path traversal attacks and blocks access to sensitive paths.
//
// Security checks:
// - Rejects paths containing ".." components (path traversal)
// - Rejects remote URL-like targets
// - Rejects scanning the filesystem root
// - Rejects paths to sensitive system directories
// - Rejects paths with null bytes (C string injection)
func validateLocalPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path is required")
	}

	// Block excessively long paths (potential DoS)
	if len(path) > 4096 {
		return fmt.Errorf("path too long (max 4096 characters)")
	}

	// Block null bytes (could truncate path in C-based operations)
	if strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("path contains invalid characters")
	}

	if strings.Contains(path, "://") {
		return fmt.Errorf("remote targets are not allowed for local path tools")
	}

	// Normalize separators before validation so Windows-style paths are checked
	// consistently even when tests run on non-Windows systems.
	slashPath := strings.ReplaceAll(path, "\\", "/")
	if strings.HasPrefix(slashPath, "//") {
		return fmt.Errorf("network paths are not allowed for local path tools")
	}
	if isWindowsDriveRelativePath(slashPath) {
		return fmt.Errorf("windows drive-relative paths are not allowed")
	}

	// Check the raw path before cleaning so "project/../secret" is rejected
	// instead of silently becoming "secret".
	if hasParentPathComponent(slashPath) {
		return fmt.Errorf("path traversal not allowed: path contains '..' component")
	}

	cleanPath := pathpkg.Clean(slashPath)
	if cleanPath == "/" {
		return fmt.Errorf("filesystem root is too broad to scan")
	}
	if drive, rest, ok := windowsDrivePath(cleanPath); ok {
		if rest == "" {
			return fmt.Errorf("filesystem root %q is too broad to scan", drive+"/")
		}
		if sensitive := windowsSensitivePath(rest); sensitive != "" {
			return fmt.Errorf("access to Windows system path %q not allowed", drive+"/"+sensitive)
		}
	}

	// Block access to sensitive system paths that should never be scanned.
	// Note: We intentionally allow /home/, /Users/, /tmp/, and /var/folders/
	// because these contain user project directories and temp files.
	sensitivePaths := []string{
		"/Applications", "/Library", "/System",
		"/bin", "/boot", "/lib", "/lib64", "/run", "/sbin", "/usr",
		"/etc", "/proc", "/sys", "/dev", "/root",
		"/private/etc", "/private/var/db", "/private/var/log", "/private/var/root",
		"/var/db", "/var/log", "/var/root",
	}
	if strings.HasPrefix(cleanPath, "/") {
		for _, sensitive := range sensitivePaths {
			if pathWithin(cleanPath, sensitive) {
				return fmt.Errorf("access to system path %q not allowed", sensitive)
			}
		}
	}

	parts := pathComponents(cleanPath)
	for i, part := range parts {
		switch part {
		case ".ssh", ".gnupg", ".aws", ".kube", ".config", "secrets":
			return fmt.Errorf("access to sensitive path component %q not allowed", part)
		case ".local":
			if i+1 < len(parts) && parts[i+1] == "share" {
				return fmt.Errorf("access to sensitive path component %q not allowed", ".local/share")
			}
		}
	}

	return nil
}

// normalizeLocalPath trims and validates a user-supplied local path, returning
// the cleaned form or an error if the path is rejected by validateLocalPath.
func normalizeLocalPath(path string) (string, error) {
	normalized := strings.TrimSpace(path)
	if err := validateLocalPath(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

// hasParentPathComponent reports whether any slash-separated segment is "..",
// which would allow escaping the intended directory via traversal.
func hasParentPathComponent(path string) bool {
	return slices.Contains(strings.Split(path, "/"), "..")
}

// pathWithin reports whether path equals root or is nested beneath it.
func pathWithin(path, root string) bool {
	return path == root || strings.HasPrefix(path, root+"/")
}

// isWindowsDriveRelativePath reports whether path is a Windows drive-relative
// path such as "C:" or "C:foo" (a drive letter without an absolute "C:/"
// prefix), which resolves against the drive's current directory and is unsafe.
func isWindowsDriveRelativePath(path string) bool {
	if len(path) < 2 || path[1] != ':' {
		return false
	}
	c := path[0]
	if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return false
	}
	return len(path) == 2 || path[2] != '/'
}

// windowsDrivePath splits a "C:/rest" style path into its uppercased drive
// ("C:") and the remainder with any leading separator removed. ok is false when
// path is not drive-qualified.
func windowsDrivePath(path string) (drive, rest string, ok bool) {
	if len(path) < 2 || path[1] != ':' {
		return "", "", false
	}
	c := path[0]
	if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return "", "", false
	}
	return strings.ToUpper(path[:1]) + ":", strings.TrimPrefix(path[2:], "/"), true
}

// windowsSensitivePath returns the leading path component when it names a
// protected Windows system directory (e.g. "Windows", "Program Files"), or ""
// when the path does not begin with one.
func windowsSensitivePath(rest string) string {
	parts := pathComponents(rest)
	if len(parts) == 0 {
		return ""
	}
	first := strings.ToLower(parts[0])
	switch first {
	case "$recycle.bin", "documents and settings", "perflogs", "program files", "program files (x86)", "programdata", "recovery", "system volume information", "windows":
		return parts[0]
	}
	return ""
}

// pathComponents splits a slash path into its non-empty segments, returning nil
// for an empty or root path.
func pathComponents(path string) []string {
	path = strings.Trim(path, "/")
	if path == "" {
		return nil
	}
	return strings.Split(path, "/")
}

// normalizeMCPEcosystems accepts the aliases agents commonly use and converts
// them to Deputy's inventory ecosystem names.
func normalizeMCPEcosystems(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, raw := range names {
		name := normalizeMCPPackageEcosystem(raw)
		if name == "" {
			continue
		}
		if name == "all" {
			return nil
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func normalizeMCPExcludePaths(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, paths := range lists {
		for _, raw := range paths {
			p := strings.TrimSpace(raw)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (s *Server) excludePaths(paths []string) []string {
	return normalizeMCPExcludePaths(s.defaultExcludePaths, paths)
}

// canonicalMCPEcosystem maps the ecosystem aliases agents and scanners use to
// Deputy's canonical ecosystem name. ok is false when name is not recognized,
// letting callers decide how to render the unknown value (see the two wrappers
// below, which differ only in that fallback).
func canonicalMCPEcosystem(name string) (canonical string, ok bool) {
	name = strings.TrimSpace(name)
	switch strings.ToLower(strings.ReplaceAll(name, "_", "-")) {
	case "github", "github action", "github actions", "github-action", "github-actions", "githubaction", "githubactions", "gha":
		return "github-actions", true
	case "cargo (crates.io)":
		return "cargo", true
	}
	if eco := ecosystem.Parse(name); eco != ecosystem.Unknown {
		return eco.String(), true
	}
	return name, false
}

// normalizeMCPPackageEcosystem canonicalizes an agent-supplied ecosystem name
// for matching, lowercasing unrecognized values so comparisons stay stable.
func normalizeMCPPackageEcosystem(name string) string {
	if canonical, ok := canonicalMCPEcosystem(name); ok {
		return canonical
	}
	return strings.ToLower(strings.TrimSpace(name))
}

// mcpOutputEcosystem canonicalizes an ecosystem name for tool output, preserving
// the scanner's original casing for values Deputy does not recognize.
func mcpOutputEcosystem(name string) string {
	canonical, _ := canonicalMCPEcosystem(name)
	return canonical
}

func mcpPURLType(ecosystemName string) string {
	switch ecosystem.Parse(ecosystemName) {
	case ecosystem.Go:
		return "golang"
	case ecosystem.RubyGems:
		return "gem"
	case ecosystem.Packagist:
		return "composer"
	default:
	}
	switch strings.ToLower(strings.TrimSpace(ecosystemName)) {
	case "github actions", "github-actions", "githubactions", "github":
		return purlx.TypeGitHubActions
	default:
		return strings.ToLower(strings.TrimSpace(ecosystemName))
	}
}

func mcpEcosystemFromPURLType(purlType string) string {
	purlType = strings.TrimSpace(purlType)
	if purlx.IsGitHubActionsType(purlType) {
		return "github-actions"
	}
	return normalizeMCPPackageEcosystem(purlType)
}

func normalizeMCPPackageVersion(ecosystemName, version string) string {
	version = strings.TrimSpace(version)
	if eco := ecosystem.Parse(ecosystemName); eco != ecosystem.Unknown {
		return eco.NormalizeVersion(version)
	}
	return version
}

func mcpPackagePURL(ecosystemName, packageName, version string) string {
	purlType := mcpPURLType(ecosystemName)
	namespace, name := mcpPackageNamespaceAndName(purlType, strings.TrimSpace(packageName))
	version = normalizeMCPPackageVersion(ecosystemName, version)
	return packageurl.NewPackageURL(purlType, namespace, name, version, nil, "").ToString()
}

func mcpPackageNamespaceAndName(purlType, name string) (string, string) {
	switch purlType {
	case packageurl.TypeMaven:
		if namespace, artifact, ok := strings.Cut(name, ":"); ok && namespace != "" && artifact != "" {
			return namespace, artifact
		}
		return splitLastSlash(name)
	case packageurl.TypeNPM:
		if strings.HasPrefix(name, "@") {
			if namespace, packageName, ok := strings.Cut(name, "/"); ok && namespace != "" && packageName != "" {
				return namespace, packageName
			}
		}
	case packageurl.TypeGolang, packageurl.TypeComposer, packageurl.TypeGithub, purlx.TypeGitHubActions:
		return splitLastSlash(name)
	}
	return "", name
}

type mcpScanPackageTarget struct {
	packageName   string
	version       string
	ecosystemName string
	purl          string
}

func resolveMCPScanPackageTarget(args ScanPackageInput) (mcpScanPackageTarget, error) {
	packageName := strings.TrimSpace(args.Name)
	versionInput := strings.TrimSpace(args.Version)
	ecosystemInput := strings.TrimSpace(args.Ecosystem)
	purlInput := strings.TrimSpace(args.PURL)

	if purlInput == "" && strings.HasPrefix(strings.ToLower(packageName), "pkg:") {
		purlInput = packageName
		packageName = ""
	}
	if purlInput != "" {
		return resolveMCPScanPackagePURLTarget(purlInput, packageName, versionInput, ecosystemInput)
	}

	if packageName == "" {
		return mcpScanPackageTarget{}, fmt.Errorf("package name is required")
	}
	if versionInput == "" {
		return mcpScanPackageTarget{}, fmt.Errorf("package version is required")
	}
	if ecosystemInput == "" {
		return mcpScanPackageTarget{}, fmt.Errorf("package ecosystem is required")
	}

	ecosystemName := normalizeMCPPackageEcosystem(ecosystemInput)
	version := normalizeMCPPackageVersion(ecosystemName, versionInput)
	return mcpScanPackageTarget{
		packageName:   packageName,
		version:       version,
		ecosystemName: ecosystemName,
		purl:          mcpPackagePURL(ecosystemName, packageName, version),
	}, nil
}

func resolveMCPScanPackagePURLTarget(purlInput, packageNameInput, versionInput, ecosystemInput string) (mcpScanPackageTarget, error) {
	parsed, err := purlx.ParseLoose(purlInput)
	if err != nil {
		return mcpScanPackageTarget{}, fmt.Errorf("invalid package purl: %w", err)
	}
	if parsed.Name == "" {
		return mcpScanPackageTarget{}, fmt.Errorf("package purl is missing package name")
	}

	ecosystemName := mcpEcosystemFromPURLType(parsed.Type)
	if ecosystemInput != "" {
		inputEcosystem := normalizeMCPPackageEcosystem(ecosystemInput)
		if inputEcosystem != ecosystemName {
			return mcpScanPackageTarget{}, fmt.Errorf("package ecosystem %q conflicts with purl type %q", ecosystemInput, parsed.Type)
		}
	}

	packageName := mcpPackageDisplayNameFromPURL(parsed)
	if packageNameInput != "" && !mcpPackageNameMatchesPURL(packageNameInput, parsed) {
		return mcpScanPackageTarget{}, fmt.Errorf("package name %q conflicts with purl package %q", packageNameInput, packageName)
	}

	version := strings.TrimSpace(parsed.Version)
	if version == "" {
		version = versionInput
	}
	if version == "" {
		return mcpScanPackageTarget{}, fmt.Errorf("package version is required (include @version in purl or provide version)")
	}
	version = normalizeMCPPackageVersion(ecosystemName, version)
	if parsed.Version != "" && versionInput != "" {
		inputVersion := normalizeMCPPackageVersion(ecosystemName, versionInput)
		if inputVersion != version {
			return mcpScanPackageTarget{}, fmt.Errorf("package version %q conflicts with purl version %q", versionInput, parsed.Version)
		}
	}

	parsed.Type = mcpPURLType(ecosystemName)
	parsed.Version = version
	return mcpScanPackageTarget{
		packageName:   packageName,
		version:       version,
		ecosystemName: ecosystemName,
		purl:          parsed.String(),
	}, nil
}

func mcpPackageDisplayNameFromPURL(purl packageurl.PackageURL) string {
	if purl.Name == "" {
		return ""
	}
	if purl.Namespace == "" {
		return purl.Name
	}
	if strings.EqualFold(purl.Type, packageurl.TypeMaven) {
		return purl.Namespace + ":" + purl.Name
	}
	return purl.Namespace + "/" + purl.Name
}

func mcpPackageNameMatchesPURL(name string, purl packageurl.PackageURL) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return true
	}
	candidates := []string{mcpPackageDisplayNameFromPURL(purl)}
	if purl.Namespace != "" {
		candidates = append(candidates, purl.Namespace+"/"+purl.Name, purl.Namespace+":"+purl.Name)
	}
	for _, candidate := range candidates {
		if strings.EqualFold(name, candidate) {
			return true
		}
	}
	return false
}

func splitLastSlash(name string) (string, string) {
	name = strings.Trim(name, "/")
	if i := strings.LastIndexByte(name, '/'); i > 0 && i < len(name)-1 {
		return name[:i], name[i+1:]
	}
	return "", name
}

// === Input/Output Types ===

// ServerInfoInput is the input for the get_server_info tool.
type ServerInfoInput struct{}

// ServerInfoResult describes the running Deputy MCP server.
type ServerInfoResult struct {
	Name                string   `json:"name"`
	Version             string   `json:"version"`
	Protocol            string   `json:"protocol"`
	Transport           string   `json:"transport,omitempty"`
	Description         string   `json:"description"`
	ProcessID           int      `json:"processId"`
	StartedAt           string   `json:"startedAt"`
	ToolCount           int      `json:"toolCount"`
	Tools               []string `json:"tools"`
	DefaultExcludePaths []string `json:"defaultExcludePaths,omitempty"`
}

// PolicyEntrypointsInput is the input for the list_policy_entrypoints tool.
type PolicyEntrypointsInput struct {
	Category string `json:"category,omitempty" jsonschema:"Optional category filter (scan, proxy, diff, container_diff, sbom, fix, triage, dockerfile, secrets, graph, server, sandbox). Legacy aliases container, service, and exec are accepted."`
}

// PolicyEntrypointsResult is the output for the list_policy_entrypoints tool.
type PolicyEntrypointsResult struct {
	Category        string                 `json:"category,omitempty"`
	EntrypointCount int                    `json:"entrypointCount"`
	Entrypoints     []PolicyEntrypointInfo `json:"entrypoints"`
}

// PolicyEntrypointInfo describes a Deputy policy entrypoint.
type PolicyEntrypointInfo struct {
	Name        string               `json:"name"`
	Category    string               `json:"category"`
	Description string               `json:"description"`
	Variables   []PolicyVariableInfo `json:"variables"`
	Helpers     []string             `json:"helpers"`
}

// PolicyVariableInfo describes a CEL variable available at a policy entrypoint.
type PolicyVariableInfo struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Description string            `json:"description,omitempty"`
	Required    bool              `json:"required"`
	Fields      []PolicyFieldInfo `json:"fields,omitempty"`
}

// PolicyFieldInfo describes a notable field within a policy variable.
type PolicyFieldInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// ExplainVulnInput is the input for the explain_vulnerability tool.
type ExplainVulnInput struct {
	ID             string `json:"id" jsonschema:"Vulnerability ID (e.g., CVE-2021-44228, GHSA-xxxx-xxxx-xxxx)"`
	ReferenceLimit *int   `json:"referenceLimit,omitempty" jsonschema:"Optional maximum number of advisory references to return. Omit or pass a negative value for all references; 0 returns none."`
}

// VulnExplanation describes a vulnerability advisory. Explanation tools return
// full advisory text; scan-like tools may omit details and truncate references.
type VulnExplanation struct {
	ID                  string           `json:"id"`
	Aliases             []string         `json:"aliases"`
	Summary             string           `json:"summary"`
	Details             string           `json:"details,omitempty"`
	Severity            string           `json:"severity"`
	SeverityType        string           `json:"severityType,omitempty"`
	FixedVersions       []string         `json:"fixedVersions"`
	PackageFixes        []VulnPackageFix `json:"packageFixes"`
	ResolvedFix         *VulnFixVerdict  `json:"resolvedFix,omitempty"`
	References          []string         `json:"references"`
	ReferenceCount      int              `json:"referenceCount,omitempty"`
	ReferencesTruncated bool             `json:"referencesTruncated,omitempty"`
	Published           string           `json:"published,omitempty"`
	Modified            string           `json:"modified,omitempty"`
}

// VulnPackageFix records fixed versions for a specific affected module path.
type VulnPackageFix struct {
	Module        string   `json:"module"`
	Ecosystem     string   `json:"ecosystem,omitempty"`
	FixedVersions []string `json:"fixedVersions"`
}

// VulnFixVerdict describes Deputy's resolved remediation outcome.
type VulnFixVerdict struct {
	Status       string `json:"status"`
	Version      string `json:"version,omitempty"`
	TargetModule string `json:"targetModule,omitempty"`
	Claimed      string `json:"claimed,omitempty"`
}

// ExplainVulnsInput is the input for the explain_vulnerabilities tool.
type ExplainVulnsInput struct {
	IDs            []string `json:"ids" jsonschema:"List of vulnerability IDs to explain"`
	ReferenceLimit *int     `json:"referenceLimit,omitempty" jsonschema:"Optional maximum number of advisory references to return per vulnerability. Omit or pass a negative value for all references; 0 returns none."`
}

// VulnsExplanation is the output for batch vulnerability explanation.
type VulnsExplanation struct {
	Vulnerabilities []VulnExplanation `json:"vulnerabilities"`
	Errors          []string          `json:"errors"`
}

// ScanPackageInput is the input for the scan_package tool.
type ScanPackageInput struct {
	PURL      string `json:"purl,omitempty" jsonschema:"Package URL, e.g. pkg:npm/lodash@4.17.21. Include @version in the PURL or provide version separately."`
	Name      string `json:"name,omitempty" jsonschema:"Package name (e.g., lodash, github.com/foo/bar), Maven coordinates (group:artifact), or a pkg: PURL."`
	Version   string `json:"version,omitempty" jsonschema:"Package version. Required unless purl or name includes a pkg: PURL with @version."`
	Ecosystem string `json:"ecosystem,omitempty" jsonschema:"Package ecosystem (e.g., npm, go, pypi, maven, cargo, github-actions). Required with split name/version input."`
}

// ScanResult is the output for package scanning.
type ScanResult struct {
	Package         string            `json:"package"`
	Version         string            `json:"version"`
	Ecosystem       string            `json:"ecosystem"`
	PURL            string            `json:"purl"`
	Vulnerabilities []VulnExplanation `json:"vulnerabilities"`
	Clean           bool              `json:"clean"`
}

// ScanDirectoryInput is the input for the scan_directory tool.
type ScanDirectoryInput struct {
	Path         string   `json:"path" jsonschema:"Path to the directory to scan"`
	Ref          string   `json:"ref,omitempty" jsonschema:"Git reference, branch, tag, or commit for repository paths. Defaults to the current working tree/HEAD."`
	Ecosystems   []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to scan (e.g., go, npm). Scans all if empty."`
	ExcludePaths []string `json:"excludePaths,omitempty" jsonschema:"Optional directory globs to skip during the walk (e.g., .bin/**, **/testdata)."`
}

// DirectoryScanResult is the output for directory scanning.
type DirectoryScanResult struct {
	Path                      string            `json:"path"`
	Ref                       string            `json:"ref,omitempty"`
	EffectiveRef              string            `json:"effectiveRef,omitempty"`
	Commit                    string            `json:"commit,omitempty"`
	PackagesScanned           int               `json:"packagesScanned"`
	VulnerabilitiesBySeverity map[string]int    `json:"vulnerabilitiesBySeverity"`
	Vulnerabilities           []VulnExplanation `json:"vulnerabilities"`
	Clean                     bool              `json:"clean"`
	ScanTime                  string            `json:"scanTime"`
	ScanTimeMs                int64             `json:"scanTimeMs"`
}

// ListDependenciesInput is the input for the list_dependencies tool.
type ListDependenciesInput struct {
	Path         string   `json:"path" jsonschema:"Path to the directory to analyze"`
	DirectOnly   bool     `json:"directOnly,omitempty" jsonschema:"If true, only list direct dependencies"`
	Ref          string   `json:"ref,omitempty" jsonschema:"Git reference, branch, tag, or commit for repository paths. Defaults to the current working tree/HEAD."`
	Ecosystems   []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
	ExcludePaths []string `json:"excludePaths,omitempty" jsonschema:"Optional directory globs to skip during the walk (e.g., .bin/**, **/testdata)."`
}

// DependencyInfo represents a single dependency.
type DependencyInfo struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Ecosystem    string            `json:"ecosystem"`
	PURL         string            `json:"purl,omitempty"`
	Direct       bool              `json:"direct"`
	Locations    []string          `json:"locations,omitempty"`
	ManifestRefs []ManifestRefInfo `json:"manifestRefs,omitempty" jsonschema:"Structured manifest declarations for this dependency, including manager, groups, and original component key where available."`
}

// ManifestRefInfo describes where a dependency was declared.
type ManifestRefInfo struct {
	Path         string   `json:"path" jsonschema:"Manifest file path containing this dependency declaration."`
	Manager      string   `json:"manager,omitempty" jsonschema:"Dependency manager or extractor that produced this declaration."`
	Groups       []string `json:"groups,omitempty" jsonschema:"Dependency groups associated with this declaration, such as direct, dev, or tools."`
	ComponentKey string   `json:"componentKey,omitempty" jsonschema:"Original manager-specific component key when it differs from the normalized dependency identity."`
}

// GraphPathNode represents a package in a dependency path with stable identity.
type GraphPathNode struct {
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	Ecosystem    string `json:"ecosystem,omitempty"`
	PURL         string `json:"purl,omitempty"`
	Direct       bool   `json:"direct"`
	Depth        int    `json:"depth"`
	Disconnected bool   `json:"disconnected,omitempty"`
	ImportStatus string `json:"importStatus,omitempty"`
}

// ListDependenciesResult is the output for the list_dependencies tool.
type ListDependenciesResult struct {
	Path                 string           `json:"path"`
	Ref                  string           `json:"ref,omitempty"`
	EffectiveRef         string           `json:"effectiveRef,omitempty"`
	Commit               string           `json:"commit,omitempty"`
	Total                int              `json:"total"`
	Direct               int              `json:"direct"`
	Transitive           int              `json:"transitive"`
	TotalDiscovered      int              `json:"totalDiscovered"`
	DirectDiscovered     int              `json:"directDiscovered"`
	TransitiveDiscovered int              `json:"transitiveDiscovered"`
	Dependencies         []DependencyInfo `json:"dependencies"`
}

// GenerateSBOMInput is the input for the generate_sbom tool.
type GenerateSBOMInput struct {
	Path           string   `json:"path" jsonschema:"Local directory or local repository checkout to analyze"`
	Ref            string   `json:"ref,omitempty" jsonschema:"Git reference (branch, tag, commit). Defaults to HEAD."`
	Format         string   `json:"format,omitempty" jsonschema:"Output format: cyclonedx-json, spdx-json, or protobom-json. Defaults to cyclonedx-json."`
	EnrichLicenses bool     `json:"enrichLicenses,omitempty" jsonschema:"Enrich SBOM with license information from deps.dev"`
	Ecosystems     []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
	ExcludePaths   []string `json:"excludePaths,omitempty" jsonschema:"Optional directory globs to skip during the walk (e.g., .bin/**, **/testdata)."`
}

// SBOMResult is the output for the generate_sbom tool.
type SBOMResult struct {
	Path         string `json:"path"`
	Ref          string `json:"ref,omitempty"`
	EffectiveRef string `json:"effectiveRef,omitempty"`
	Commit       string `json:"commit,omitempty"`
	Format       string `json:"format"`
	Components   int    `json:"components"`
	SBOM         string `json:"sbom"`
}

// GetRemediationInput is the input for the get_remediation tool.
type GetRemediationInput struct {
	Path         string   `json:"path" jsonschema:"Path to the directory to analyze for remediation"`
	Ref          string   `json:"ref,omitempty" jsonschema:"Git reference, branch, tag, or commit for repository paths. Defaults to the current working tree/HEAD."`
	Ecosystems   []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
	ExcludePaths []string `json:"excludePaths,omitempty" jsonschema:"Optional directory globs to skip during the walk (e.g., .bin/**, **/testdata)."`
}

// RemediationCommand represents a remediation action.
type RemediationCommand struct {
	Package       string   `json:"package,omitempty"`
	Version       string   `json:"version,omitempty"`
	PURL          string   `json:"purl,omitempty"`
	TargetVersion string   `json:"targetVersion,omitempty"`
	TargetModule  string   `json:"targetModule,omitempty"`
	Migration     bool     `json:"migration,omitempty"`
	Manager       string   `json:"manager"`
	Command       string   `json:"command"`
	Path          string   `json:"path,omitempty"`
	Hint          string   `json:"hint,omitempty"`
	IsDirect      bool     `json:"isDirect"`
	Executable    bool     `json:"executable"`
	Groups        []string `json:"groups,omitempty"`
}

// GetRemediationResult is the output for the get_remediation tool.
type GetRemediationResult struct {
	Path                     string               `json:"path"`
	Ref                      string               `json:"ref,omitempty"`
	EffectiveRef             string               `json:"effectiveRef,omitempty"`
	Commit                   string               `json:"commit,omitempty"`
	VulnerabilitiesFound     int                  `json:"vulnerabilitiesFound"`
	RemediableCount          int                  `json:"remediableCount"`
	MigrationCount           int                  `json:"migrationCount"`
	UnfixableCount           int                  `json:"unfixableCount"`
	CommandCount             int                  `json:"commandCount"`
	ExecutableCommandCount   int                  `json:"executableCommandCount"`
	ManualCommandCount       int                  `json:"manualCommandCount"`
	Commands                 []RemediationCommand `json:"commands"`
	StdlibUpgrade            string               `json:"stdlibUpgrade,omitempty"`
	UnfixableVulnerabilities []string             `json:"unfixableVulnerabilities,omitempty"`
}

// AnalyzeGraphInput is the input for the analyze_dependency_graph tool.
type AnalyzeGraphInput struct {
	Path               string   `json:"path" jsonschema:"Path to the directory to analyze"`
	Ref                string   `json:"ref,omitempty" jsonschema:"Git reference, branch, tag, or commit for repository paths. Defaults to the current working tree/HEAD."`
	TargetPURL         string   `json:"targetPurl,omitempty" jsonschema:"Optional PURL to find paths to (e.g., pkg:npm/lodash@4.17.15)"`
	Ecosystems         []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
	ExcludePaths       []string `json:"excludePaths,omitempty" jsonschema:"Optional directory globs to skip during the walk (e.g., .bin/**, **/testdata)."`
	ResolveTransitives bool     `json:"resolveTransitives,omitempty" jsonschema:"If true, use package registry, deps.dev, and Git lookups to resolve more precise transitive graph edges. Slower and may require network access."`
	Extended           bool     `json:"extended,omitempty" jsonschema:"If true, include extended graph metadata where supported, such as Go import status for required and declared modules."`
}

// GraphPath represents a dependency path.
type GraphPath struct {
	Nodes       []string        `json:"nodes"`
	NodeDetails []GraphPathNode `json:"nodeDetails"`
	Depth       int             `json:"depth"`
}

// GraphStats contains statistics about the dependency graph.
type GraphStats struct {
	TotalNodes         int                      `json:"totalNodes"`
	DirectNodes        int                      `json:"directNodes"`
	TransitiveNodes    int                      `json:"transitiveNodes"`
	MaxDepth           int                      `json:"maxDepth"`
	MaxConnectedDepth  int                      `json:"maxConnectedDepth"`
	DisconnectedNodes  int                      `json:"disconnectedNodes"`
	VulnerableNodes    int                      `json:"vulnerableNodes"`
	Ecosystems         map[string]int           `json:"ecosystems"`
	ImportStatusCounts *GraphImportStatusCounts `json:"importStatusCounts,omitempty"`
}

// GraphImportStatusCounts summarizes extended-mode graph node status.
type GraphImportStatusCounts struct {
	Imported int `json:"imported"`
	Required int `json:"required"`
	Declared int `json:"declared"`
}

// AnalyzeGraphResult is the output for the analyze_dependency_graph tool.
type AnalyzeGraphResult struct {
	Path                     string             `json:"path"`
	Ref                      string             `json:"ref,omitempty"`
	EffectiveRef             string             `json:"effectiveRef,omitempty"`
	Commit                   string             `json:"commit,omitempty"`
	Stats                    GraphStats         `json:"stats"`
	VulnerablePaths          []GraphPath        `json:"vulnerablePaths"`
	VulnerablePathCount      int                `json:"vulnerablePathCount"`
	VulnerablePathsTruncated bool               `json:"vulnerablePathsTruncated"`
	PathsToTarget            []GraphPath        `json:"pathsToTarget"`
	PathsToTargetTruncated   bool               `json:"pathsToTargetTruncated"`
	Target                   *GraphTargetResult `json:"target,omitempty"`
}

// GraphTargetResult summarizes targetPurl matching and path resolution.
type GraphTargetResult struct {
	Query        string          `json:"query"`
	Found        bool            `json:"found"`
	PathCount    int             `json:"pathCount"`
	MatchedPURLs []string        `json:"matchedPurls"`
	MatchedNodes []GraphPathNode `json:"matchedNodes,omitempty"`
	Message      string          `json:"message,omitempty"`
}

// GraphWhyInput is the input for the graph_why tool.
type GraphWhyInput struct {
	Path               string   `json:"path" jsonschema:"Path to the directory to analyze"`
	Package            string   `json:"package" jsonschema:"Package name, name@version, or PURL to trace (e.g., lodash, golang.org/x/crypto@v0.17.0, pkg:npm/lodash@4.17.21)"`
	Ref                string   `json:"ref,omitempty" jsonschema:"Git reference, branch, tag, or commit for repository paths. Defaults to the current working tree/HEAD."`
	ShowAll            bool     `json:"showAll,omitempty" jsonschema:"Return up to 100 dependency path examples instead of the default 10; use pathCount and pathsTruncated to detect sampling."`
	Ecosystems         []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
	ExcludePaths       []string `json:"excludePaths,omitempty" jsonschema:"Optional directory globs to skip during the walk (e.g., .bin/**, **/testdata)."`
	ResolveTransitives bool     `json:"resolveTransitives,omitempty" jsonschema:"If true, use package registry, deps.dev, and Git lookups to resolve more precise transitive graph edges. Slower and may require network access."`
	Extended           bool     `json:"extended,omitempty" jsonschema:"If true, include extended graph metadata where supported, such as Go import status for required and declared modules."`
}

// GraphWhyResult is the output for the graph_why tool.
type GraphWhyResult struct {
	Package        string         `json:"package"`
	Version        string         `json:"version,omitempty"`
	PURL           string         `json:"purl,omitempty"`
	Ref            string         `json:"ref,omitempty"`
	EffectiveRef   string         `json:"effectiveRef,omitempty"`
	Commit         string         `json:"commit,omitempty"`
	Direct         bool           `json:"direct"`
	Found          bool           `json:"found"`
	MatchedNode    *GraphPathNode `json:"matchedNode,omitempty"`
	Paths          []GraphPath    `json:"paths"`
	PathCount      int            `json:"pathCount"`
	PathsTruncated bool           `json:"pathsTruncated"`
	Message        string         `json:"message,omitempty"`
}

// GraphNeedsInput is the input for the graph_needs tool.
type GraphNeedsInput struct {
	Path               string   `json:"path" jsonschema:"Path to the directory to analyze"`
	Package            string   `json:"package" jsonschema:"Package name, name@version, or PURL to find dependents of"`
	Ref                string   `json:"ref,omitempty" jsonschema:"Git reference, branch, tag, or commit for repository paths. Defaults to the current working tree/HEAD."`
	Ecosystems         []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
	ExcludePaths       []string `json:"excludePaths,omitempty" jsonschema:"Optional directory globs to skip during the walk (e.g., .bin/**, **/testdata)."`
	ResolveTransitives bool     `json:"resolveTransitives,omitempty" jsonschema:"If true, use package registry, deps.dev, and Git lookups to resolve more precise transitive graph edges. Slower and may require network access."`
	Extended           bool     `json:"extended,omitempty" jsonschema:"If true, include extended graph metadata where supported, such as Go import status for required and declared modules."`
}

// GraphNeedsResult is the output for the graph_needs tool.
type GraphNeedsResult struct {
	Package         string           `json:"package"`
	Version         string           `json:"version,omitempty"`
	PURL            string           `json:"purl,omitempty"`
	Ref             string           `json:"ref,omitempty"`
	EffectiveRef    string           `json:"effectiveRef,omitempty"`
	Commit          string           `json:"commit,omitempty"`
	Direct          bool             `json:"direct"`
	Found           bool             `json:"found"`
	MatchedNode     *GraphPathNode   `json:"matchedNode,omitempty"`
	Dependents      []DependencyInfo `json:"dependents"`
	DirectCount     int              `json:"directCount"`
	TransitiveCount int              `json:"transitiveCount"`
	Message         string           `json:"message,omitempty"`
}

// TriageInput is the input for the triage_vulnerabilities tool.
type TriageInput struct {
	Path         string   `json:"path" jsonschema:"Path to the directory to analyze"`
	Ref          string   `json:"ref,omitempty" jsonschema:"Git reference, branch, tag, or commit for repository paths. Defaults to the current working tree/HEAD."`
	Ecosystems   []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
	ExcludePaths []string `json:"excludePaths,omitempty" jsonschema:"Optional directory globs to skip during the walk (e.g., .bin/**, **/testdata)."`
}

// TriagedVuln represents a prioritized vulnerability.
type TriagedVuln struct {
	ID             string           `json:"id"`
	Severity       string           `json:"severity"`
	SeverityType   string           `json:"severityType,omitempty"`
	Package        string           `json:"package"`
	Version        string           `json:"version"`
	PURL           string           `json:"purl,omitempty"`
	IsDirect       bool             `json:"isDirect"`
	HasFix         bool             `json:"hasFix"`
	FixedVersions  []string         `json:"fixedVersions"`
	PackageFixes   []VulnPackageFix `json:"packageFixes"`
	ResolvedFix    *VulnFixVerdict  `json:"resolvedFix,omitempty"`
	Summary        string           `json:"summary"`
	Priority       string           `json:"priority"` // "critical", "high", "medium", "low"
	PriorityReason string           `json:"priorityReason"`
}

// TriageResult is the output for the triage_vulnerabilities tool.
type TriageResult struct {
	Path                      string        `json:"path"`
	Ref                       string        `json:"ref,omitempty"`
	EffectiveRef              string        `json:"effectiveRef,omitempty"`
	Commit                    string        `json:"commit,omitempty"`
	TotalVulnerabilities      int           `json:"totalVulnerabilities"`
	CriticalCount             int           `json:"criticalCount"`
	HighCount                 int           `json:"highCount"`
	MediumCount               int           `json:"mediumCount"`
	LowCount                  int           `json:"lowCount"`
	UnknownCount              int           `json:"unknownCount"`
	FixableCount              int           `json:"fixableCount"`
	MigrationCount            int           `json:"migrationCount"`
	UnfixableCount            int           `json:"unfixableCount"`
	DirectVulnerabilities     int           `json:"directVulnerabilities"`
	TransitiveVulnerabilities int           `json:"transitiveVulnerabilities"`
	DirectFixableCount        int           `json:"directFixableCount"`
	TransitiveFixableCount    int           `json:"transitiveFixableCount"`
	Vulnerabilities           []TriagedVuln `json:"vulnerabilities"`
	Recommendations           []string      `json:"recommendations"`
}

// ScanContainerInput is the input for the scan_container tool.
type ScanContainerInput struct {
	Image    string `json:"image" jsonschema:"Container image reference (e.g., nginx:1.25, ghcr.io/owner/app:v1.0.0, docker-daemon://myapp:latest)"`
	Platform string `json:"platform,omitempty" jsonschema:"Target platform (e.g., linux/amd64, linux/arm64). Defaults to current platform."`
}

// ContainerScanResult is the output for container scanning.
type ContainerScanResult struct {
	Image                     string            `json:"image"`
	Platform                  string            `json:"platform,omitempty"`
	PackagesScanned           int               `json:"packagesScanned"`
	VulnerabilitiesBySeverity map[string]int    `json:"vulnerabilitiesBySeverity"`
	Vulnerabilities           []VulnExplanation `json:"vulnerabilities"`
	Clean                     bool              `json:"clean"`
	ScanTime                  string            `json:"scanTime"`
	ScanTimeMs                int64             `json:"scanTimeMs"`
}

// DiffRefsInput is the input for the diff_refs tool.
type DiffRefsInput struct {
	Path         string   `json:"path" jsonschema:"Path to the repository for Git refs. Leave empty for container image diffs."`
	BaseRef      string   `json:"baseRef" jsonschema:"Base Git reference (branch, tag, commit) or container image reference"`
	TargetRef    string   `json:"targetRef" jsonschema:"Target Git reference or container image reference to compare against"`
	Platform     string   `json:"platform,omitempty" jsonschema:"Target platform for container image diffs (e.g., linux/amd64, linux/arm64). Ignored for Git ref diffs."`
	Ecosystems   []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include (for Git diffs)"`
	ExcludePaths []string `json:"excludePaths,omitempty" jsonschema:"Optional directory globs to skip during Git ref scans (e.g., .bin/**, **/testdata)."`
}

// DependencyChange represents a change to a dependency.
type DependencyChange struct {
	Name          string `json:"name"`
	BaseVersion   string `json:"baseVersion,omitempty"`
	TargetVersion string `json:"targetVersion,omitempty"`
	PURL          string `json:"purl,omitempty"`
	ChangeType    string `json:"changeType"` // "added", "removed", "upgraded", "downgraded", "updated"
	IsDirect      bool   `json:"isDirect"`
	Ecosystem     string `json:"ecosystem"`
}

// DiffRefsResult is the output for the diff_refs tool.
type DiffRefsResult struct {
	Path                 string             `json:"path,omitempty"`
	BaseRef              string             `json:"baseRef"`
	TargetRef            string             `json:"targetRef"`
	BaseCommit           string             `json:"baseCommit,omitempty"`
	TargetCommit         string             `json:"targetCommit,omitempty"`
	Platform             string             `json:"platform,omitempty"`
	IsContainerDiff      bool               `json:"isContainerDiff"`
	Changes              []DependencyChange `json:"changes"`
	AddedCount           int                `json:"addedCount"`
	RemovedCount         int                `json:"removedCount"`
	UpdatedCount         int                `json:"updatedCount"`
	Vulnerabilities      []VulnExplanation  `json:"vulnerabilities,omitempty"`
	VulnerabilitySummary map[string]int     `json:"vulnerabilitySummary,omitempty"`
	VulnerabilityChanges []DiffVulnChange   `json:"vulnerabilityChanges,omitempty"`
	ContainerSummary     *ContainerSummary  `json:"containerSummary,omitempty"`
}

// DiffVulnChange represents a vulnerability delta between container images.
type DiffVulnChange struct {
	ID            string   `json:"id"`
	Aliases       []string `json:"aliases,omitempty"`
	ChangeType    string   `json:"changeType"`
	Severity      string   `json:"severity,omitempty"`
	Package       string   `json:"package,omitempty"`
	Ecosystem     string   `json:"ecosystem,omitempty"`
	BaseVersion   string   `json:"baseVersion,omitempty"`
	TargetVersion string   `json:"targetVersion,omitempty"`
	FixedVersions []string `json:"fixedVersions,omitempty"`
	Summary       string   `json:"summary,omitempty"`
	Published     string   `json:"published,omitempty"`
}

// ContainerSummary provides container-specific diff totals.
type ContainerSummary struct {
	PackagesAdded          int  `json:"packagesAdded"`
	PackagesRemoved        int  `json:"packagesRemoved"`
	PackagesUpgraded       int  `json:"packagesUpgraded"`
	PackagesDowngraded     int  `json:"packagesDowngraded"`
	VulnerabilitiesAdded   int  `json:"vulnerabilitiesAdded"`
	VulnerabilitiesRemoved int  `json:"vulnerabilitiesRemoved"`
	VulnerabilitiesFixed   int  `json:"vulnerabilitiesFixed"`
	LayersAdded            int  `json:"layersAdded"`
	LayersRemoved          int  `json:"layersRemoved"`
	ConfigChanged          bool `json:"configChanged"`
}

// === Tool Implementations ===

func (s *Server) getServerInfo(ctx context.Context, req *mcp.CallToolRequest, args ServerInfoInput) (*mcp.CallToolResult, ServerInfoResult, error) {
	return nil, s.serverInfo(), nil
}

func (s *Server) serverInfo() ServerInfoResult {
	tools := slices.Clone(s.toolNames)
	excludePaths := slices.Clone(s.defaultExcludePaths)
	return ServerInfoResult{
		Name:                "deputy",
		Version:             version.Value,
		Protocol:            "mcp",
		Description:         "Deputy MCP server for software supply chain security",
		ProcessID:           os.Getpid(),
		StartedAt:           s.startedAt.Format(time.RFC3339),
		ToolCount:           len(tools),
		Tools:               tools,
		DefaultExcludePaths: excludePaths,
	}
}

func (s *Server) listPolicyEntrypoints(ctx context.Context, req *mcp.CallToolRequest, args PolicyEntrypointsInput) (*mcp.CallToolResult, PolicyEntrypointsResult, error) {
	startTime := time.Now()
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Default)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.list_policy_entrypoints",
		trace.WithAttributes(otel.AttrMCPTool.String("list_policy_entrypoints")))
	defer span.End()

	category := policy.NormalizeCategory(args.Category)
	logs.Debug(ctx, "MCP tool invoked", "tool", "list_policy_entrypoints", "category", category)

	if s.clients.Policy == nil {
		err := fmt.Errorf("policy service client is not configured")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "list_policy_entrypoints", time.Since(startTime).Seconds(), false)
		return nil, PolicyEntrypointsResult{}, err
	}

	resp, err := s.clients.Policy.ListEntrypoints(ctx, connect.NewRequest(&policyv1.ListEntrypointsRequest{
		Category: category,
	}))
	if err != nil {
		err = fmt.Errorf("list policy entrypoints: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "list_policy_entrypoints", time.Since(startTime).Seconds(), false)
		return nil, PolicyEntrypointsResult{}, err
	}

	result := PolicyEntrypointsResult{
		Category:    category,
		Entrypoints: make([]PolicyEntrypointInfo, 0, len(resp.Msg.GetEntrypoints())),
	}
	for _, entrypoint := range resp.Msg.GetEntrypoints() {
		result.Entrypoints = append(result.Entrypoints, policyEntrypointToMCP(entrypoint))
	}
	result.EntrypointCount = len(result.Entrypoints)

	span.SetAttributes(attribute.Int("deputy.mcp.policy_entrypoint_count", result.EntrypointCount))
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "list_policy_entrypoints", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "list_policy_entrypoints", "category", category, "entrypoints", result.EntrypointCount)

	return nil, result, nil
}

// policyEntrypointToMCP converts the API policy metadata shape into the compact
// JSON object returned by the MCP tool.
func policyEntrypointToMCP(info *policyv1.EntrypointInfo) PolicyEntrypointInfo {
	if info == nil {
		return PolicyEntrypointInfo{}
	}
	return PolicyEntrypointInfo{
		Name:        info.GetName(),
		Category:    info.GetCategory(),
		Description: info.GetDescription(),
		Variables:   policyVariablesToMCP(info.GetVariables()),
		Helpers:     slices.Clone(info.GetHelpers()),
	}
}

// policyVariablesToMCP preserves variable order from the policy service so
// required bindings appear before optional bindings in MCP responses.
func policyVariablesToMCP(vars []*policyv1.VariableInfo) []PolicyVariableInfo {
	out := make([]PolicyVariableInfo, 0, len(vars))
	for _, variable := range vars {
		if variable == nil {
			continue
		}
		out = append(out, PolicyVariableInfo{
			Name:        variable.GetName(),
			Type:        variable.GetType(),
			Description: variable.GetDescription(),
			Required:    variable.GetRequired(),
			Fields:      policyFieldsToMCP(variable.GetFields()),
		})
	}
	return out
}

// policyFieldsToMCP converts notable nested variable fields for MCP clients
// that want to guide CEL authoring without loading proto descriptors.
func policyFieldsToMCP(fields []*policyv1.FieldInfo) []PolicyFieldInfo {
	out := make([]PolicyFieldInfo, 0, len(fields))
	for _, field := range fields {
		if field == nil {
			continue
		}
		out = append(out, PolicyFieldInfo{
			Name:        field.GetName(),
			Type:        field.GetType(),
			Description: field.GetDescription(),
		})
	}
	return out
}

func (s *Server) explainVulnerability(ctx context.Context, req *mcp.CallToolRequest, args ExplainVulnInput) (*mcp.CallToolResult, VulnExplanation, error) {
	startTime := time.Now()

	// Apply timeout for quick operations
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Default)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.explain_vulnerability",
		trace.WithAttributes(otel.AttrMCPTool.String("explain_vulnerability")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "explain_vulnerability", "vuln_id", args.ID)

	vulnID := strings.TrimSpace(args.ID)
	if vulnID == "" {
		err := fmt.Errorf("vulnerability ID is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "explain_vulnerability", time.Since(startTime).Seconds(), false)
		return nil, VulnExplanation{}, err
	}

	span.SetAttributes(otel.AttrMCPVulnerabilityID.String(vulnID))

	// Use the VulnerabilityService via clients.Advisory
	advisoryReq := connect.NewRequest(&vulnerabilityv1.GetAdvisoryRequest{
		Id: vulnID,
	})

	resp, err := s.clients.Advisory.GetAdvisory(ctx, advisoryReq)
	if err != nil {
		err = fmt.Errorf("failed to fetch vulnerability %s: %w", vulnID, err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "explain_vulnerability", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Failed to fetch vulnerability", "vuln_id", vulnID, "error", err)
		return nil, VulnExplanation{}, err
	}

	if !resp.Msg.GetFound() {
		err = fmt.Errorf("vulnerability %s not found", vulnID)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "explain_vulnerability", time.Since(startTime).Seconds(), false)
		return nil, VulnExplanation{}, err
	}

	// Convert proto Advisory to MCP VulnExplanation
	advisory := resp.Msg.GetAdvisory()
	explanation := advisoryToExplanation(advisory, referenceLimitForMCP(args.ReferenceLimit))

	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "explain_vulnerability", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "explain_vulnerability", "vuln_id", vulnID)

	return nil, explanation, nil
}

func (s *Server) explainVulnerabilities(ctx context.Context, req *mcp.CallToolRequest, args ExplainVulnsInput) (*mcp.CallToolResult, VulnsExplanation, error) {
	startTime := time.Now()

	// Apply timeout for quick operations (scaled by count)
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Default)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.explain_vulnerabilities",
		trace.WithAttributes(otel.AttrMCPTool.String("explain_vulnerabilities")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "explain_vulnerabilities", "count", len(args.IDs))

	ids, err := normalizeMCPVulnerabilityIDs(args.IDs)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "explain_vulnerabilities", time.Since(startTime).Seconds(), false)
		return nil, VulnsExplanation{}, err
	}

	span.SetAttributes(otel.AttrMCPVulnerabilityCount.Int(len(ids)))

	uniqueIDs := uniqueMCPVulnerabilityIDs(ids)
	advisoryReq := connect.NewRequest(&vulnerabilityv1.GetAdvisoriesRequest{
		Ids: uniqueIDs,
	})
	resp, err := s.clients.Advisory.GetAdvisories(ctx, advisoryReq)
	if err != nil {
		err = fmt.Errorf("failed to fetch vulnerabilities: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "explain_vulnerabilities", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Failed to fetch vulnerabilities", "count", len(uniqueIDs), "error", err)
		return nil, VulnsExplanation{}, err
	}

	result := VulnsExplanation{
		Vulnerabilities: make([]VulnExplanation, 0, len(ids)),
		Errors:          make([]string, 0),
	}

	advisories := resp.Msg.GetAdvisories()
	notFound := stringSet(resp.Msg.GetNotFound())
	errorsByID := resp.Msg.GetErrors()
	for _, id := range ids {
		if advisory := advisoryForMCPVulnerabilityID(advisories, id); advisory != nil {
			result.Vulnerabilities = append(result.Vulnerabilities, advisoryToExplanation(advisory, referenceLimitForMCP(args.ReferenceLimit)))
			continue
		}
		if message, ok := errorsByID[id]; ok {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %s", id, message))
			continue
		}
		if _, ok := notFound[id]; ok {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: vulnerability %s not found", id, id))
			continue
		}
		result.Errors = append(result.Errors, fmt.Sprintf("%s: vulnerability %s not found", id, id))
	}

	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "explain_vulnerabilities", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "explain_vulnerabilities", "found", len(result.Vulnerabilities), "errors", len(result.Errors))

	return nil, result, nil
}

func normalizeMCPVulnerabilityIDs(ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("at least one vulnerability ID is required")
	}
	out := make([]string, 0, len(ids))
	for i, rawID := range ids {
		id := strings.TrimSpace(rawID)
		if id == "" {
			return nil, fmt.Errorf("ids[%d] is required", i)
		}
		out = append(out, id)
	}
	return out, nil
}

func uniqueMCPVulnerabilityIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		key := strings.ToUpper(id)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, id)
	}
	return out
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func advisoryForMCPVulnerabilityID(advisories map[string]*vulnerabilityv1.Advisory, id string) *vulnerabilityv1.Advisory {
	if advisory := advisories[id]; advisory != nil {
		return advisory
	}
	for _, advisory := range advisories {
		if advisory == nil {
			continue
		}
		if strings.EqualFold(advisory.GetId(), id) {
			return advisory
		}
		if slices.ContainsFunc(advisory.GetAliases(), func(alias string) bool {
			return strings.EqualFold(alias, id)
		}) {
			return advisory
		}
	}
	return nil
}

func (s *Server) scanPackage(ctx context.Context, req *mcp.CallToolRequest, args ScanPackageInput) (*mcp.CallToolResult, ScanResult, error) {
	startTime := time.Now()

	// Apply timeout for quick operations
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Default)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.scan_package",
		trace.WithAttributes(otel.AttrMCPTool.String("scan_package")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "scan_package", "package", args.Name, "version", args.Version, "ecosystem", args.Ecosystem)

	target, err := resolveMCPScanPackageTarget(args)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "scan_package", time.Since(startTime).Seconds(), false)
		return nil, ScanResult{}, err
	}

	span.SetAttributes(
		attribute.String("deputy.mcp.package", target.packageName),
		attribute.String("deputy.mcp.version", target.version),
		attribute.String("deputy.mcp.ecosystem", target.ecosystemName),
	)

	// Use the scan service via clients
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: target.purl,
		Options: &scanv1.ScanOptions{
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_PURL,
			},
		},
	})

	resp, err := s.clients.Vulns.Scan(ctx, scanReq)
	if err != nil {
		err = fmt.Errorf("failed to scan package: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "scan_package", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Package scan failed", "package", target.packageName, "error", err)
		return nil, ScanResult{}, err
	}

	result := ScanResult{
		Package:         target.packageName,
		Version:         target.version,
		Ecosystem:       target.ecosystemName,
		PURL:            target.purl,
		Vulnerabilities: make([]VulnExplanation, 0),
	}

	scanResult := internalproto.ScanningResultFromProto(resp.Msg)
	consolidated := vulnerability.ConsolidateAll(scanResult.Findings, scanResult.Advisories)
	for _, vuln := range consolidated.Vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, compactVulnExplanationFromConsolidated(vuln))
	}

	result.Clean = len(result.Vulnerabilities) == 0

	span.SetAttributes(otel.AttrMCPVulnerabilityCount.Int(len(result.Vulnerabilities)))
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "scan_package", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "scan_package", "package", target.packageName, "vulns", len(result.Vulnerabilities), "clean", result.Clean)

	return nil, result, nil
}

func (s *Server) scanDirectory(ctx context.Context, req *mcp.CallToolRequest, args ScanDirectoryInput) (*mcp.CallToolResult, DirectoryScanResult, error) {
	startTime := time.Now()

	// Apply timeout for scan operations
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Scan)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.scan_directory",
		trace.WithAttributes(otel.AttrMCPTool.String("scan_directory")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "scan_directory", "path", args.Path)

	// Validate path to prevent path traversal and access to sensitive directories.
	targetPath, err := normalizeLocalPath(args.Path)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "scan_directory", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Invalid path in scan_directory", "path", args.Path, "error", err)
		return nil, DirectoryScanResult{}, err
	}

	span.SetAttributes(otel.AttrTargetPath.String(targetPath))

	// Build proto request
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: targetPath,
		Options: &scanv1.ScanOptions{
			Ref:          strings.TrimSpace(args.Ref),
			Ecosystems:   normalizeMCPEcosystems(args.Ecosystems),
			ExcludePaths: s.excludePaths(args.ExcludePaths),
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_DIR,
			},
		},
	})

	resp, err := s.clients.Vulns.Scan(ctx, scanReq)
	if err != nil {
		err = fmt.Errorf("scan failed: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "scan_directory", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Directory scan failed", "path", targetPath, "error", err)
		return nil, DirectoryScanResult{}, err
	}

	scanResult := resp.Msg
	internalScanResult := internalproto.ScanningResultFromProto(scanResult)
	consolidated := vulnerability.ConsolidateAll(internalScanResult.Findings, internalScanResult.Advisories)
	ref, effectiveRef, commit := mcpTargetRef(scanResult.GetTarget())
	result := DirectoryScanResult{
		Path:            targetPath,
		Ref:             ref,
		EffectiveRef:    effectiveRef,
		Commit:          commit,
		PackagesScanned: int(scanResult.PackagesScanned),
		VulnerabilitiesBySeverity: map[string]int{
			"critical": int(consolidated.Stats.GetCritical()),
			"high":     int(consolidated.Stats.GetHigh()),
			"medium":   int(consolidated.Stats.GetMedium()),
			"low":      int(consolidated.Stats.GetLow()),
			"unknown":  int(consolidated.Stats.GetUnknown()),
		},
		Vulnerabilities: make([]VulnExplanation, 0),
		Clean:           consolidated.Stats.GetUnique() == 0,
		ScanTime:        time.Since(startTime).String(),
		ScanTimeMs:      time.Since(startTime).Milliseconds(),
	}

	for _, vuln := range consolidated.Vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, compactVulnExplanationFromConsolidated(vuln))
	}

	span.SetAttributes(
		otel.AttrMCPPackageCount.Int(int(scanResult.PackagesScanned)),
		otel.AttrMCPVulnerabilityCount.Int(int(consolidated.Stats.GetUnique())),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "scan_directory", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "scan_directory", "path", targetPath, "packages", result.PackagesScanned, "vulns", consolidated.Stats.GetUnique(), "clean", result.Clean)

	return nil, result, nil
}

func (s *Server) listDependencies(ctx context.Context, req *mcp.CallToolRequest, args ListDependenciesInput) (*mcp.CallToolResult, ListDependenciesResult, error) {
	startTime := time.Now()

	// Apply timeout for scan operations (listing requires scanning)
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Scan)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.list_dependencies",
		trace.WithAttributes(otel.AttrMCPTool.String("list_dependencies")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "list_dependencies", "path", args.Path, "direct_only", args.DirectOnly)

	// Validate path to prevent path traversal and access to sensitive directories.
	targetPath, err := normalizeLocalPath(args.Path)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "list_dependencies", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Invalid path in list_dependencies", "path", args.Path, "error", err)
		return nil, ListDependenciesResult{}, err
	}

	span.SetAttributes(otel.AttrTargetPath.String(targetPath))

	// Build proto request for ListPackages
	listReq := connect.NewRequest(&listv1.ListPackagesRequest{
		Target: targetPath,
		Options: &listv1.ListOptions{
			Ref:          strings.TrimSpace(args.Ref),
			Ecosystems:   normalizeMCPEcosystems(args.Ecosystems),
			ExcludePaths: s.excludePaths(args.ExcludePaths),
			OnlyDirect:   args.DirectOnly,
		},
	})

	resp, err := s.clients.Packages.ListPackages(ctx, listReq)
	if err != nil {
		err = fmt.Errorf("failed to analyze dependencies: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "list_dependencies", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "List dependencies failed", "path", targetPath, "error", err)
		return nil, ListDependenciesResult{}, err
	}

	listResult := resp.Msg
	ref, effectiveRef, commit := mcpTargetRef(listResult.GetTarget())
	result := ListDependenciesResult{
		Path:                 targetPath,
		Ref:                  ref,
		EffectiveRef:         effectiveRef,
		Commit:               commit,
		Dependencies:         make([]DependencyInfo, 0, len(listResult.Packages)),
		TotalDiscovered:      int(listResult.Stats.GetTotalPackages()),
		DirectDiscovered:     int(listResult.Stats.GetDirectPackages()),
		TransitiveDiscovered: int(listResult.Stats.GetTransitivePackages()),
	}

	for _, pkg := range listResult.Packages {
		dep := DependencyInfo{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Ecosystem:    mcpOutputEcosystem(pkg.Ecosystem),
			Direct:       pkg.Direct,
			Locations:    pkg.Locations,
			PURL:         pkg.Purl,
			ManifestRefs: manifestRefsForMCP(pkg.GetManifestRefs()),
		}
		result.Dependencies = append(result.Dependencies, dep)
		result.Total++
		if pkg.Direct {
			result.Direct++
		} else {
			result.Transitive++
		}
	}

	span.SetAttributes(otel.AttrMCPPackageCount.Int(result.TotalDiscovered))
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "list_dependencies", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "list_dependencies", "path", targetPath, "returned", result.Total, "total_discovered", result.TotalDiscovered, "direct", result.Direct, "transitive", result.Transitive)

	return nil, result, nil
}

func (s *Server) generateSBOM(ctx context.Context, req *mcp.CallToolRequest, args GenerateSBOMInput) (*mcp.CallToolResult, SBOMResult, error) {
	startTime := time.Now()

	// Apply timeout for SBOM generation
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.SBOM)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.generate_sbom",
		trace.WithAttributes(otel.AttrMCPTool.String("generate_sbom")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "generate_sbom", "path", args.Path, "format", args.Format)

	// Validate path to prevent path traversal and access to sensitive directories.
	targetPath, err := normalizeLocalPath(args.Path)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "generate_sbom", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Invalid path in generate_sbom", "path", args.Path, "error", err)
		return nil, SBOMResult{}, err
	}

	format, err := flags.NormalizeSBOMOutputFormat(args.Format)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "generate_sbom", time.Since(startTime).Seconds(), false)
		return nil, SBOMResult{}, err
	}

	span.SetAttributes(
		otel.AttrTargetPath.String(targetPath),
		attribute.String("deputy.mcp.sbom_format", format),
	)

	opts := sbomx.Options{
		Ref:            strings.TrimSpace(args.Ref),
		Ecosystems:     normalizeMCPEcosystems(args.Ecosystems),
		ExcludePaths:   s.excludePaths(args.ExcludePaths),
		EnrichLicenses: args.EnrichLicenses,
		LicenseSource:  "depsdev",
	}

	sbomResult, err := sbomx.Generate(ctx, targetPath, opts)
	if err != nil {
		err = fmt.Errorf("failed to generate SBOM: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "generate_sbom", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "SBOM generation failed", "path", targetPath, "error", err)
		return nil, SBOMResult{}, err
	}

	// Serialize to requested format
	var sb strings.Builder
	switch format {
	case "cyclonedx-json":
		if err := sbomx.WriteCycloneDXJSON(sbomResult.Document, &sb); err != nil {
			err = fmt.Errorf("failed to serialize SBOM: %w", err)
			otel.SetSpanError(span, err)
			otel.RecordMCPToolCall(ctx, "generate_sbom", time.Since(startTime).Seconds(), false)
			return nil, SBOMResult{}, err
		}
	case "spdx-json":
		if err := sbomx.WriteSPDXJSON(sbomResult.Document, &sb); err != nil {
			err = fmt.Errorf("failed to serialize SBOM: %w", err)
			otel.SetSpanError(span, err)
			otel.RecordMCPToolCall(ctx, "generate_sbom", time.Since(startTime).Seconds(), false)
			return nil, SBOMResult{}, err
		}
	case "protobom-json":
		if err := sbomx.WriteProtobomJSON(sbomResult.Document, &sb); err != nil {
			err = fmt.Errorf("failed to serialize SBOM: %w", err)
			otel.SetSpanError(span, err)
			otel.RecordMCPToolCall(ctx, "generate_sbom", time.Since(startTime).Seconds(), false)
			return nil, SBOMResult{}, err
		}
	}

	components := 0
	if sbomResult.Document != nil && sbomResult.Document.NodeList != nil {
		components = len(sbomResult.Document.NodeList.Nodes)
	}

	span.SetAttributes(otel.AttrMCPPackageCount.Int(components))
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "generate_sbom", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "generate_sbom", "path", targetPath, "format", format, "components", components)

	return nil, SBOMResult{
		Path:         targetPath,
		Ref:          sbomResult.Ref,
		EffectiveRef: sbomResult.Target.EffectiveRef,
		Commit:       sbomResult.Commit,
		Format:       format,
		Components:   components,
		SBOM:         sb.String(),
	}, nil
}

func (s *Server) getRemediation(ctx context.Context, req *mcp.CallToolRequest, args GetRemediationInput) (*mcp.CallToolResult, GetRemediationResult, error) {
	startTime := time.Now()

	// Apply timeout for scan operations (remediation requires scanning)
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Scan)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.get_remediation",
		trace.WithAttributes(otel.AttrMCPTool.String("get_remediation")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "get_remediation", "path", args.Path)

	// Validate path to prevent path traversal and access to sensitive directories.
	targetPath, err := normalizeLocalPath(args.Path)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "get_remediation", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Invalid path in get_remediation", "path", args.Path, "error", err)
		return nil, GetRemediationResult{}, err
	}

	span.SetAttributes(otel.AttrTargetPath.String(targetPath))

	// Build proto request
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: targetPath,
		Options: &scanv1.ScanOptions{
			Ref:          strings.TrimSpace(args.Ref),
			Ecosystems:   normalizeMCPEcosystems(args.Ecosystems),
			ExcludePaths: s.excludePaths(args.ExcludePaths),
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_DIR,
			},
		},
	})

	resp, err := s.clients.Vulns.Scan(ctx, scanReq)
	if err != nil {
		err = fmt.Errorf("scan failed: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "get_remediation", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Remediation scan failed", "path", targetPath, "error", err)
		return nil, GetRemediationResult{}, err
	}

	// Convert proto response to internal types for remediation analysis
	scanResult := internalproto.ScanningResultFromProto(resp.Msg)

	// Consolidate vulnerabilities for remediation analysis
	consolidated := vulnerability.ConsolidateAll(scanResult.Findings, scanResult.Advisories)

	// Get remediation commands
	commands, stdlibUpgrade := remediation.CommandsFromConsolidated(consolidated.Vulnerabilities)
	commands = remediation.ApplyGuidance(commands, remediation.MCPGuidance())

	// Identify unfixable vulnerabilities
	var unfixable []string
	remediableCount := 0
	migrationCount := 0
	for _, v := range consolidated.Vulnerabilities {
		remediable, migration := remediationDisposition(v)
		if remediable {
			remediableCount++
			if migration {
				migrationCount++
			}
		} else {
			unfixable = append(unfixable, v.PrimaryID)
		}
	}

	ref, effectiveRef, commit := mcpTargetRef(resp.Msg.GetTarget())
	result := GetRemediationResult{
		Path:                     targetPath,
		Ref:                      ref,
		EffectiveRef:             effectiveRef,
		Commit:                   commit,
		VulnerabilitiesFound:     int(scanResult.Stats.Unique),
		RemediableCount:          remediableCount,
		MigrationCount:           migrationCount,
		UnfixableCount:           len(unfixable),
		CommandCount:             len(commands),
		Commands:                 make([]RemediationCommand, 0, len(commands)),
		StdlibUpgrade:            stdlibUpgrade,
		UnfixableVulnerabilities: unfixable,
	}

	for _, cmd := range commands {
		if cmd.Executable {
			result.ExecutableCommandCount++
		} else {
			result.ManualCommandCount++
		}
		result.Commands = append(result.Commands, RemediationCommand{
			Package:       cmd.Package,
			Version:       cmd.Version,
			PURL:          cmd.PURL,
			TargetVersion: cmd.TargetVersion,
			TargetModule:  cmd.TargetModule,
			Migration:     cmd.Migration,
			Manager:       cmd.Manager,
			Command:       cmd.Command,
			Path:          cmd.Path,
			Hint:          cmd.Hint,
			IsDirect:      cmd.IsDirect,
			Executable:    cmd.Executable,
			Groups:        cmd.Groups,
		})
	}

	span.SetAttributes(
		otel.AttrMCPVulnerabilityCount.Int(result.VulnerabilitiesFound),
		attribute.Int("deputy.mcp.remediable_count", result.RemediableCount),
		attribute.Int("deputy.mcp.command_count", result.CommandCount),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "get_remediation", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "get_remediation", "path", targetPath, "vulns", result.VulnerabilitiesFound, "remediable", result.RemediableCount, "unfixable", result.UnfixableCount)

	return nil, result, nil
}

func (s *Server) analyzeDependencyGraph(ctx context.Context, req *mcp.CallToolRequest, args AnalyzeGraphInput) (*mcp.CallToolResult, AnalyzeGraphResult, error) {
	startTime := time.Now()

	// Apply timeout for graph analysis
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Graph)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.analyze_dependency_graph",
		trace.WithAttributes(otel.AttrMCPTool.String("analyze_dependency_graph")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "analyze_dependency_graph", "path", args.Path, "target_purl", args.TargetPURL)

	if args.Path == "" {
		err := fmt.Errorf("path is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "analyze_dependency_graph", time.Since(startTime).Seconds(), false)
		return nil, AnalyzeGraphResult{}, err
	}
	targetPath, err := normalizeLocalPath(args.Path)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "analyze_dependency_graph", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Invalid path in analyze_dependency_graph", "path", args.Path, "error", err)
		return nil, AnalyzeGraphResult{}, err
	}
	targetPURL := strings.TrimSpace(args.TargetPURL)
	var parsedTargetPURL packageurl.PackageURL
	hasTargetPURL := false
	if targetPURL != "" {
		parsed, err := purlx.ParseLoose(targetPURL)
		if err != nil {
			err = fmt.Errorf("targetPurl must be a valid PURL: %w", err)
			otel.SetSpanError(span, err)
			otel.RecordMCPToolCall(ctx, "analyze_dependency_graph", time.Since(startTime).Seconds(), false)
			return nil, AnalyzeGraphResult{}, err
		}
		parsedTargetPURL = parsed
		hasTargetPURL = true
	}

	span.SetAttributes(otel.AttrTargetPath.String(targetPath))

	depGraph, target, err := s.buildDependencyGraph(ctx, targetPath, args.Ref, args.Ecosystems, args.ExcludePaths, args.ResolveTransitives, args.Extended)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "analyze_dependency_graph", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Graph analysis failed", "path", targetPath, "error", err)
		return nil, AnalyzeGraphResult{}, err
	}
	if err := s.annotateGraphVulnerabilities(ctx, targetPath, args.Ref, args.Ecosystems, args.ExcludePaths, depGraph); err != nil {
		err = fmt.Errorf("scan failed: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "analyze_dependency_graph", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Graph vulnerability annotation failed", "path", targetPath, "error", err)
		return nil, AnalyzeGraphResult{}, err
	}

	ref, effectiveRef, commit := mcpTargetRef(target)
	result := AnalyzeGraphResult{
		Path:            targetPath,
		Ref:             ref,
		EffectiveRef:    effectiveRef,
		Commit:          commit,
		VulnerablePaths: make([]GraphPath, 0),
		PathsToTarget:   make([]GraphPath, 0),
	}

	// Get stats
	result.Stats = mcpGraphStats(depGraph.Stats())

	// Find vulnerable paths
	vulnPaths := depGraph.VulnerablePaths()
	result.VulnerablePathCount = len(vulnPaths)
	result.VulnerablePathsTruncated = len(vulnPaths) > maxMCPVulnerablePaths
	result.VulnerablePaths = make([]GraphPath, 0, min(len(vulnPaths), maxMCPVulnerablePaths))
	for _, path := range vulnPaths {
		if len(result.VulnerablePaths) >= maxMCPVulnerablePaths {
			break
		}
		result.VulnerablePaths = append(result.VulnerablePaths, graphPathToMCP(path))
	}

	// If a target PURL is specified, find paths to matching graph nodes.
	if hasTargetPURL {
		resolvedPURLs := resolveGraphTargetPURLs(depGraph, parsedTargetPURL)
		result.Target = &GraphTargetResult{
			Query:        targetPURL,
			Found:        len(resolvedPURLs) > 0,
			MatchedPURLs: append([]string{}, resolvedPURLs...),
		}
		for _, resolvedPURL := range resolvedPURLs {
			if node := depGraph.Node(resolvedPURL); node != nil {
				result.Target.MatchedNodes = append(result.Target.MatchedNodes, graphNodeToMCP(node))
			}
			paths := depGraph.PathsTo(resolvedPURL)
			result.Target.PathCount += len(paths)
			for _, path := range paths {
				if len(result.PathsToTarget) >= maxMCPPathsToTarget {
					break
				}
				result.PathsToTarget = append(result.PathsToTarget, graphPathToMCP(path))
			}
		}
		result.PathsToTargetTruncated = result.Target.PathCount > len(result.PathsToTarget)
		result.Target.Message = graphTargetMessage(result.Target)
	}

	span.SetAttributes(
		otel.AttrMCPPackageCount.Int(result.Stats.TotalNodes),
		attribute.Int("deputy.mcp.vulnerable_nodes", result.Stats.VulnerableNodes),
		otel.AttrMCPGraphPathCount.Int(len(result.VulnerablePaths)),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "analyze_dependency_graph", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "analyze_dependency_graph", "path", targetPath, "nodes", result.Stats.TotalNodes, "vulnerable_nodes", result.Stats.VulnerableNodes)

	return nil, result, nil
}

func graphTargetMessage(target *GraphTargetResult) string {
	switch {
	case target == nil:
		return ""
	case !target.Found:
		return "Target PURL was not found in the dependency graph"
	case target.PathCount == 0:
		return "Target PURL is present in the dependency graph, but no dependency path from a direct/root dependency was resolved"
	case target.PathCount == 1:
		return "1 dependency path to target found"
	default:
		return fmt.Sprintf("%d dependency paths to target found", target.PathCount)
	}
}

// buildDependencyGraph builds the dependency graph for a target and returns it
// along with the resolved target metadata (ref/effectiveRef/commit) so callers
// can echo which Git snapshot answered the query.
func (s *Server) buildDependencyGraph(ctx context.Context, targetPath, ref string, ecosystems, excludePaths []string, resolveTransitives, extended bool) (*graph.Graph, *targetv1.Target, error) {
	if s.clients == nil || s.clients.Graph == nil {
		return nil, nil, fmt.Errorf("graph service is not configured")
	}

	resp, err := s.clients.Graph.BuildGraph(ctx, connect.NewRequest(&graphv1.BuildGraphRequest{
		Target: targetPath,
		Options: &graphv1.GraphOptions{
			Ecosystems:   normalizeMCPEcosystems(ecosystems),
			ExcludePaths: s.excludePaths(excludePaths),
			Ref:          strings.TrimSpace(ref),
			UseProxy:     resolveTransitives,
			UseGit:       resolveTransitives,
			Extended:     extended,
		},
	}))
	if err != nil {
		return nil, nil, fmt.Errorf("build graph: %w", err)
	}
	depGraph := graph.FromProto(resp.Msg.GetNodes(), resp.Msg.GetEdges(), resp.Msg.GetRoots())
	if depGraph == nil {
		return nil, nil, fmt.Errorf("build graph returned no graph")
	}
	return depGraph, resp.Msg.GetTarget(), nil
}

func (s *Server) annotateGraphVulnerabilities(ctx context.Context, targetPath, ref string, ecosystems, excludePaths []string, depGraph *graph.Graph) error {
	if depGraph == nil {
		return nil
	}
	if s.clients == nil || s.clients.Vulns == nil {
		return fmt.Errorf("scan service is not configured")
	}
	resp, err := s.clients.Vulns.Scan(ctx, connect.NewRequest(&scanv1.ScanRequest{
		Target: targetPath,
		Options: &scanv1.ScanOptions{
			Ecosystems:             normalizeMCPEcosystems(ecosystems),
			ExcludePaths:           s.excludePaths(excludePaths),
			Ref:                    strings.TrimSpace(ref),
			DisableFixVerification: true,
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_DIR,
			},
		},
	}))
	if err != nil {
		return err
	}
	scanResult := internalproto.ScanningResultFromProto(resp.Msg)
	depGraph.AnnotateVulns(scanResult.Findings, scanResult.Advisories)
	return nil
}

func mcpGraphStats(stats *graphv1.GraphStats) GraphStats {
	ecosystems := make(map[string]int)
	for k, v := range stats.GetEcosystems() {
		ecosystems[mcpOutputEcosystem(k)] += int(v)
	}
	result := GraphStats{
		TotalNodes:        int(stats.GetTotalNodes()),
		DirectNodes:       int(stats.GetDirectNodes()),
		TransitiveNodes:   int(stats.GetTransitiveNodes()),
		MaxDepth:          int(stats.GetMaxDepth()),
		MaxConnectedDepth: int(stats.GetMaxConnectedDepth()),
		DisconnectedNodes: int(stats.GetDisconnectedNodes()),
		VulnerableNodes:   int(stats.GetVulnerableNodes()),
		Ecosystems:        ecosystems,
	}
	if counts := stats.GetImportStatusCounts(); counts != nil {
		result.ImportStatusCounts = &GraphImportStatusCounts{
			Imported: int(counts.GetImported()),
			Required: int(counts.GetRequired()),
			Declared: int(counts.GetDeclared()),
		}
	}
	return result
}

// === Graph, Triage, and Container Tool Implementations ===

func (s *Server) graphWhy(ctx context.Context, req *mcp.CallToolRequest, args GraphWhyInput) (*mcp.CallToolResult, GraphWhyResult, error) {
	startTime := time.Now()

	// Apply timeout for graph analysis
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Graph)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.graph_why",
		trace.WithAttributes(otel.AttrMCPTool.String("graph_why")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "graph_why", "path", args.Path, "package", args.Package)

	packageQuery := strings.TrimSpace(args.Package)

	// Validate path to prevent path traversal and access to sensitive directories.
	targetPath, err := normalizeLocalPath(args.Path)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "graph_why", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Invalid path in graph_why", "path", args.Path, "error", err)
		return nil, GraphWhyResult{}, err
	}
	if packageQuery == "" {
		err := fmt.Errorf("package name is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "graph_why", time.Since(startTime).Seconds(), false)
		return nil, GraphWhyResult{}, err
	}

	span.SetAttributes(
		otel.AttrTargetPath.String(targetPath),
		otel.AttrMCPGraphPackage.String(packageQuery),
	)

	depGraph, target, err := s.buildDependencyGraph(ctx, targetPath, args.Ref, args.Ecosystems, args.ExcludePaths, args.ResolveTransitives, args.Extended)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "graph_why", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Graph why failed", "path", targetPath, "package", packageQuery, "error", err)
		return nil, GraphWhyResult{}, err
	}
	ref, effectiveRef, commit := mcpTargetRef(target)

	// Find matching nodes using ranked matching
	matches := findMatchingNodes(depGraph, packageQuery)
	if len(matches) == 0 {
		span.SetAttributes(otel.AttrMCPGraphFound.Bool(false))
		otel.SetSpanOK(span)
		otel.RecordMCPToolCall(ctx, "graph_why", time.Since(startTime).Seconds(), true)
		logs.Debug(ctx, "MCP tool completed", "tool", "graph_why", "package", packageQuery, "found", false)
		return nil, GraphWhyResult{
			Package:      packageQuery,
			Ref:          ref,
			EffectiveRef: effectiveRef,
			Commit:       commit,
			Found:        false,
			Paths:        []GraphPath{},
			Message:      fmt.Sprintf("Package %q not found in dependency graph", packageQuery),
		}, nil
	}

	// Use the best match
	match := matches[0]
	result := GraphWhyResult{
		Package:      match.Name,
		Version:      match.Version,
		PURL:         match.Purl,
		Ref:          ref,
		EffectiveRef: effectiveRef,
		Commit:       commit,
		Direct:       match.Direct,
		Found:        true,
		MatchedNode:  graphPathNodePtr(match),
		Paths:        make([]GraphPath, 0),
	}

	// Return direct dependencies as a one-node path so agents can consume
	// direct and transitive graph answers with the same structured shape.
	if match.Direct {
		result.Paths = []GraphPath{graphPathToMCP(graph.Path{match})}
		result.PathCount = 1
		result.Message = "Direct dependency"
		span.SetAttributes(
			otel.AttrMCPGraphFound.Bool(true),
			otel.AttrMCPGraphDirect.Bool(true),
			otel.AttrMCPGraphPathCount.Int(result.PathCount),
		)
		otel.SetSpanOK(span)
		otel.RecordMCPToolCall(ctx, "graph_why", time.Since(startTime).Seconds(), true)
		logs.Debug(ctx, "MCP tool completed", "tool", "graph_why", "package", packageQuery, "found", true, "direct", true, "paths", result.PathCount)
		return nil, result, nil
	}

	// Find paths to the package
	paths := depGraph.PathsTo(match.Purl)
	if len(paths) == 0 {
		result.Message = graphquery.NoDependencyPathMessage(match, args.ResolveTransitives, args.Extended)
		span.SetAttributes(
			otel.AttrMCPGraphFound.Bool(true),
			otel.AttrMCPGraphPathCount.Int(0),
		)
		otel.SetSpanOK(span)
		otel.RecordMCPToolCall(ctx, "graph_why", time.Since(startTime).Seconds(), true)
		logs.Debug(ctx, "MCP tool completed", "tool", "graph_why", "package", packageQuery, "found", true, "paths", 0)
		return nil, result, nil
	}

	// Convert paths
	limit := maxMCPGraphWhyPaths
	if args.ShowAll {
		limit = maxMCPGraphWhyShowAllPaths
	}
	result.Paths = make([]GraphPath, 0, min(len(paths), limit))
	for i, path := range paths {
		if i >= limit {
			break
		}
		result.Paths = append(result.Paths, graphPathToMCP(path))
	}
	result.PathCount = len(paths)
	result.PathsTruncated = len(paths) > limit

	if len(paths) == 1 {
		result.Message = "1 dependency path found"
	} else {
		result.Message = fmt.Sprintf("%d dependency paths found", len(paths))
	}

	span.SetAttributes(
		otel.AttrMCPGraphFound.Bool(true),
		otel.AttrMCPGraphDirect.Bool(false),
		otel.AttrMCPGraphPathCount.Int(result.PathCount),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "graph_why", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "graph_why", "package", packageQuery, "found", true, "paths", result.PathCount)

	return nil, result, nil
}

func graphPathNodePtr(node *graph.Node) *GraphPathNode {
	out := graphNodeToMCP(node)
	return &out
}

func (s *Server) graphNeeds(ctx context.Context, req *mcp.CallToolRequest, args GraphNeedsInput) (*mcp.CallToolResult, GraphNeedsResult, error) {
	startTime := time.Now()

	// Apply timeout for graph analysis
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Graph)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.graph_needs",
		trace.WithAttributes(otel.AttrMCPTool.String("graph_needs")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "graph_needs", "path", args.Path, "package", args.Package)

	packageQuery := strings.TrimSpace(args.Package)

	// Validate path to prevent path traversal and access to sensitive directories.
	targetPath, err := normalizeLocalPath(args.Path)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "graph_needs", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Invalid path in graph_needs", "path", args.Path, "error", err)
		return nil, GraphNeedsResult{}, err
	}
	if packageQuery == "" {
		err := fmt.Errorf("package name is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "graph_needs", time.Since(startTime).Seconds(), false)
		return nil, GraphNeedsResult{}, err
	}

	span.SetAttributes(
		otel.AttrTargetPath.String(targetPath),
		otel.AttrMCPGraphPackage.String(packageQuery),
	)

	depGraph, target, err := s.buildDependencyGraph(ctx, targetPath, args.Ref, args.Ecosystems, args.ExcludePaths, args.ResolveTransitives, args.Extended)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "graph_needs", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Graph needs failed", "path", targetPath, "package", packageQuery, "error", err)
		return nil, GraphNeedsResult{}, err
	}
	ref, effectiveRef, commit := mcpTargetRef(target)

	// Find best matching node
	match := findBestMatchingNode(depGraph, packageQuery)
	if match == nil {
		span.SetAttributes(otel.AttrMCPGraphFound.Bool(false))
		otel.SetSpanOK(span)
		otel.RecordMCPToolCall(ctx, "graph_needs", time.Since(startTime).Seconds(), true)
		logs.Debug(ctx, "MCP tool completed", "tool", "graph_needs", "package", packageQuery, "found", false)
		return nil, GraphNeedsResult{
			Package:      packageQuery,
			Ref:          ref,
			EffectiveRef: effectiveRef,
			Commit:       commit,
			Found:        false,
			Dependents:   []DependencyInfo{},
			Message:      fmt.Sprintf("Package %q not found in dependency graph", packageQuery),
		}, nil
	}

	result := GraphNeedsResult{
		Package:      match.Name,
		Version:      match.Version,
		PURL:         match.Purl,
		Ref:          ref,
		EffectiveRef: effectiveRef,
		Commit:       commit,
		Direct:       match.Direct,
		Found:        true,
		MatchedNode:  graphPathNodePtr(match),
		Dependents:   []DependencyInfo{},
	}

	// Collect ancestors (packages that depend on this one). Ancestors is a BFS
	// over the same parent index a direct Parents() call would use, so an empty
	// result here means the node genuinely has no dependents (e.g. a root/direct
	// dependency); NoDependentsMessage explains that case below.
	for ancestor := range depGraph.Ancestors(match.Purl) {
		dep := DependencyInfo{
			Name:      ancestor.Name,
			Version:   ancestor.Version,
			Ecosystem: mcpOutputEcosystem(ancestor.Ecosystem),
			PURL:      ancestor.Purl,
			Direct:    ancestor.Direct,
			Locations: ancestor.Locations,
		}
		result.Dependents = append(result.Dependents, dep)
		if ancestor.Direct {
			result.DirectCount++
		} else {
			result.TransitiveCount++
		}
	}

	if len(result.Dependents) == 0 {
		result.Message = graphquery.NoDependentsMessage(match, args.ResolveTransitives)
	}
	sortDependencyInfos(result.Dependents)

	span.SetAttributes(
		otel.AttrMCPGraphFound.Bool(true),
		attribute.Int("deputy.mcp.dependent_count", len(result.Dependents)),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "graph_needs", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "graph_needs", "package", packageQuery, "found", true, "dependents", len(result.Dependents))

	return nil, result, nil
}

func sortDependencyInfos(deps []DependencyInfo) {
	slices.SortFunc(deps, func(a, b DependencyInfo) int {
		if a.Direct != b.Direct {
			if a.Direct {
				return -1
			}
			return 1
		}
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.PURL, b.PURL)
	})
}

func (s *Server) triageVulnerabilities(ctx context.Context, req *mcp.CallToolRequest, args TriageInput) (*mcp.CallToolResult, TriageResult, error) {
	startTime := time.Now()

	// Apply timeout for scan operations (triage requires scanning)
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Scan)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.triage_vulnerabilities",
		trace.WithAttributes(otel.AttrMCPTool.String("triage_vulnerabilities")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "triage_vulnerabilities", "path", args.Path)

	if args.Path == "" {
		err := fmt.Errorf("path is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "triage_vulnerabilities", time.Since(startTime).Seconds(), false)
		return nil, TriageResult{}, err
	}
	targetPath, err := normalizeLocalPath(args.Path)
	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "triage_vulnerabilities", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Invalid path in triage_vulnerabilities", "path", args.Path, "error", err)
		return nil, TriageResult{}, err
	}

	span.SetAttributes(otel.AttrTargetPath.String(targetPath))

	// Build proto request
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: targetPath,
		Options: &scanv1.ScanOptions{
			Ref:          strings.TrimSpace(args.Ref),
			Ecosystems:   normalizeMCPEcosystems(args.Ecosystems),
			ExcludePaths: s.excludePaths(args.ExcludePaths),
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_DIR,
			},
		},
	})

	resp, err := s.clients.Vulns.Scan(ctx, scanReq)
	if err != nil {
		err = fmt.Errorf("scan failed: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "triage_vulnerabilities", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Triage scan failed", "path", targetPath, "error", err)
		return nil, TriageResult{}, err
	}

	// Convert proto response to internal types
	scanResult := internalproto.ScanningResultFromProto(resp.Msg)
	ref, effectiveRef, commit := mcpTargetRef(resp.Msg.GetTarget())

	result := TriageResult{
		Path:            targetPath,
		Ref:             ref,
		EffectiveRef:    effectiveRef,
		Commit:          commit,
		Vulnerabilities: make([]TriagedVuln, 0),
		Recommendations: make([]string, 0),
	}

	// Consolidate vulnerabilities
	consolidated := vulnerability.ConsolidateAll(scanResult.Findings, scanResult.Advisories)

	// Process each vulnerability
	for _, v := range consolidated.Vulnerabilities {
		hasFix, migration := remediationDisposition(v)
		severity := severityStringForMCP(v.Severity, v.SeverityType)

		// Determine priority based on severity, fixability, and direct dependency
		priority, reason := calculatePriority(severity, hasFix, v.IsDirect)

		triaged := TriagedVuln{
			ID:             v.PrimaryID,
			Severity:       severity,
			SeverityType:   strings.TrimSpace(v.SeverityType),
			Package:        v.Package,
			Version:        v.Version,
			PURL:           v.PURL,
			IsDirect:       v.IsDirect,
			HasFix:         hasFix,
			FixedVersions:  stringsForMCP(v.FixedVersions),
			PackageFixes:   packageFixesToMCP(v.PackageFixes),
			ResolvedFix:    fixVerdictToMCP(v.Fix),
			Summary:        v.Summary,
			Priority:       priority,
			PriorityReason: reason,
		}

		result.Vulnerabilities = append(result.Vulnerabilities, triaged)

		// Count by severity
		switch severity {
		case "CRITICAL":
			result.CriticalCount++
		case "HIGH":
			result.HighCount++
		case "MEDIUM":
			result.MediumCount++
		case "LOW":
			result.LowCount++
		case "UNKNOWN":
			result.UnknownCount++
		default:
			result.UnknownCount++
		}

		if hasFix {
			result.FixableCount++
			if v.IsDirect {
				result.DirectFixableCount++
			} else {
				result.TransitiveFixableCount++
			}
			if migration {
				result.MigrationCount++
			}
		} else {
			result.UnfixableCount++
		}

		if v.IsDirect {
			result.DirectVulnerabilities++
		} else {
			result.TransitiveVulnerabilities++
		}
	}

	result.TotalVulnerabilities = len(consolidated.Vulnerabilities)

	// Sort by priority (critical first)
	sortTriagedVulns(result.Vulnerabilities)

	// Generate recommendations
	result.Recommendations = generateRecommendations(result)

	span.SetAttributes(
		otel.AttrMCPTriageCount.Int(result.TotalVulnerabilities),
		attribute.Int("deputy.mcp.critical_count", result.CriticalCount),
		attribute.Int("deputy.mcp.fixable_count", result.FixableCount),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "triage_vulnerabilities", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "triage_vulnerabilities", "path", targetPath, "total", result.TotalVulnerabilities, "critical", result.CriticalCount, "fixable", result.FixableCount)

	return nil, result, nil
}

// calculatePriority determines the priority of a vulnerability.
func calculatePriority(severity string, hasFix, isDirect bool) (string, string) {
	if severity == "CRITICAL" && hasFix && isDirect {
		return "critical", "Critical severity, fixable, in direct dependency"
	}
	if severity == "CRITICAL" && hasFix {
		return "critical", "Critical severity with fix available in transitive dependency"
	}
	if severity == "CRITICAL" {
		return "high", "Critical severity but no fix available"
	}
	if severity == "HIGH" && hasFix && isDirect {
		return "high", "High severity, fixable, in direct dependency"
	}
	if severity == "HIGH" && hasFix {
		return "high", "High severity with fix available in transitive dependency"
	}
	if severity == "HIGH" {
		return "medium", "High severity but no fix available"
	}
	if severity == "MEDIUM" && hasFix && isDirect {
		return "medium", "Medium severity, fixable, in direct dependency"
	}
	if severity == "MEDIUM" && hasFix {
		return "low", "Medium severity with fix available in transitive dependency"
	}
	if severity == "MEDIUM" {
		return "low", "Medium severity"
	}
	if severity == "LOW" && hasFix && isDirect {
		return "low", "Low severity, fixable, in direct dependency"
	}
	if severity == "LOW" && hasFix {
		return "low", "Low severity with fix available in transitive dependency"
	}
	if severity == "LOW" {
		return "low", "Low severity"
	}
	if hasFix && isDirect {
		return "low", "Unknown severity, fixable, in direct dependency"
	}
	if hasFix {
		return "low", "Unknown severity with fix available in transitive dependency"
	}
	return "low", "Unknown severity"
}

// sortTriagedVulns sorts vulnerabilities by priority, breaking ties on ID so
// the ordering is deterministic for agents diffing successive triage results.
func sortTriagedVulns(vulns []TriagedVuln) {
	priorityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	slices.SortFunc(vulns, func(a, b TriagedVuln) int {
		if c := cmp.Compare(priorityOrder[a.Priority], priorityOrder[b.Priority]); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
}

// generateRecommendations creates actionable recommendations from triage results.
func generateRecommendations(result TriageResult) []string {
	var recs []string

	if result.CriticalCount > 0 {
		recs = append(recs, fmt.Sprintf("Address %d critical vulnerability(ies) immediately", result.CriticalCount))
	}
	if result.DirectFixableCount > 0 {
		recs = append(recs, fmt.Sprintf("Update or migrate direct dependencies to fix %d vulnerability(ies)", result.DirectFixableCount))
	}
	if result.MigrationCount > 0 {
		recs = append(recs, fmt.Sprintf("Plan package or module migrations for %d vulnerability(ies)", result.MigrationCount))
	}
	if result.TransitiveVulnerabilities > 0 {
		recs = append(recs, fmt.Sprintf("Review %d transitive dependency vulnerability(ies) - may require updating or migrating direct dependencies", result.TransitiveVulnerabilities))
	}
	if result.UnfixableCount > 0 {
		recs = append(recs, fmt.Sprintf("Monitor %d vulnerability(ies) without fixes for updates", result.UnfixableCount))
	}
	if result.TotalVulnerabilities == 0 {
		recs = append(recs, "No vulnerabilities found - continue regular dependency updates")
	}

	return recs
}

func (s *Server) scanContainer(ctx context.Context, req *mcp.CallToolRequest, args ScanContainerInput) (*mcp.CallToolResult, ContainerScanResult, error) {
	startTime := time.Now()

	// Apply timeout for scan operations
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Scan)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.scan_container",
		trace.WithAttributes(otel.AttrMCPTool.String("scan_container")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "scan_container", "image", args.Image, "platform", args.Platform)

	imageRef := strings.TrimSpace(args.Image)
	if imageRef == "" {
		err := fmt.Errorf("image is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "scan_container", time.Since(startTime).Seconds(), false)
		return nil, ContainerScanResult{}, err
	}
	platform := strings.TrimSpace(args.Platform)

	span.SetAttributes(otel.AttrMCPImage.String(imageRef))

	// Build proto request for container image scan
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: imageRef,
		Options: &scanv1.ScanOptions{
			Platform: platform,
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE,
			},
		},
	})

	resp, err := s.clients.Vulns.Scan(ctx, scanReq)
	if err != nil {
		err = fmt.Errorf("container scan failed: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "scan_container", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Container scan failed", "image", imageRef, "error", err)
		return nil, ContainerScanResult{}, err
	}

	scanResult := resp.Msg
	internalScanResult := internalproto.ScanningResultFromProto(scanResult)
	consolidated := vulnerability.ConsolidateAll(internalScanResult.Findings, internalScanResult.Advisories)
	result := ContainerScanResult{
		Image:           imageRef,
		Platform:        platform,
		PackagesScanned: int(scanResult.PackagesScanned),
		VulnerabilitiesBySeverity: map[string]int{
			"critical": int(consolidated.Stats.GetCritical()),
			"high":     int(consolidated.Stats.GetHigh()),
			"medium":   int(consolidated.Stats.GetMedium()),
			"low":      int(consolidated.Stats.GetLow()),
			"unknown":  int(consolidated.Stats.GetUnknown()),
		},
		Vulnerabilities: make([]VulnExplanation, 0),
		Clean:           consolidated.Stats.GetUnique() == 0,
		ScanTime:        time.Since(startTime).String(),
		ScanTimeMs:      time.Since(startTime).Milliseconds(),
	}

	for _, vuln := range consolidated.Vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, compactVulnExplanationFromConsolidated(vuln))
	}

	span.SetAttributes(
		otel.AttrMCPPackageCount.Int(int(scanResult.PackagesScanned)),
		otel.AttrMCPVulnerabilityCount.Int(int(consolidated.Stats.GetUnique())),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "scan_container", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "scan_container", "image", imageRef, "packages", result.PackagesScanned, "vulns", consolidated.Stats.GetUnique(), "clean", result.Clean)

	return nil, result, nil
}

func (s *Server) diffRefs(ctx context.Context, req *mcp.CallToolRequest, args DiffRefsInput) (*mcp.CallToolResult, DiffRefsResult, error) {
	startTime := time.Now()

	// Apply timeout for scan operations (diff involves scanning both refs)
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Scan)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.diff_refs",
		trace.WithAttributes(otel.AttrMCPTool.String("diff_refs")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "diff_refs", "base_ref", args.BaseRef, "target_ref", args.TargetRef)

	args.Path = strings.TrimSpace(args.Path)
	args.BaseRef = strings.TrimSpace(args.BaseRef)
	args.TargetRef = strings.TrimSpace(args.TargetRef)
	args.Platform = strings.TrimSpace(args.Platform)

	if args.BaseRef == "" {
		err := fmt.Errorf("baseRef is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "diff_refs", time.Since(startTime).Seconds(), false)
		return nil, DiffRefsResult{}, err
	}
	if args.TargetRef == "" {
		err := fmt.Errorf("targetRef is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "diff_refs", time.Since(startTime).Seconds(), false)
		return nil, DiffRefsResult{}, err
	}

	span.SetAttributes(
		otel.AttrMCPBaseRef.String(args.BaseRef),
		otel.AttrMCPTargetRef.String(args.TargetRef),
	)

	// Validate the path before routing. Routing calls os.Stat on args.Path to
	// detect a Git working tree, so validate first to avoid probing the
	// filesystem with an unvalidated (e.g. traversal) path.
	if strings.TrimSpace(args.Path) != "" {
		if _, err := normalizeLocalPath(args.Path); err != nil {
			err = fmt.Errorf("invalid path: %w", err)
			otel.SetSpanError(span, err)
			otel.RecordMCPToolCall(ctx, "diff_refs", time.Since(startTime).Seconds(), false)
			return nil, DiffRefsResult{}, err
		}
	}

	if isMixedContainerRefInput(args) {
		err := fmt.Errorf("baseRef and targetRef must both be Git refs or both be container image refs")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "diff_refs", time.Since(startTime).Seconds(), false)
		return nil, DiffRefsResult{}, err
	}

	// Check if this looks like a container image diff.
	isContainerDiff := isContainerDiffInput(args)

	var result DiffRefsResult
	var err error
	if isContainerDiff {
		_, result, err = s.diffContainerImages(ctx, args)
	} else {
		_, result, err = s.diffGitRefs(ctx, args)
	}

	if err != nil {
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "diff_refs", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Diff refs failed", "base_ref", args.BaseRef, "target_ref", args.TargetRef, "error", err)
		return nil, DiffRefsResult{}, err
	}

	span.SetAttributes(
		otel.AttrMCPChangeCount.Int(len(result.Changes)),
		attribute.Bool("deputy.mcp.is_container_diff", isContainerDiff),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "diff_refs", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "diff_refs", "base_ref", args.BaseRef, "target_ref", args.TargetRef, "changes", len(result.Changes), "is_container", isContainerDiff)

	return nil, result, nil
}

// diffContainerImages compares two container images.
func (s *Server) diffContainerImages(ctx context.Context, args DiffRefsInput) (*mcp.CallToolResult, DiffRefsResult, error) {
	baseRef := strings.TrimSpace(args.BaseRef)
	targetRef := strings.TrimSpace(args.TargetRef)
	platform := strings.TrimSpace(args.Platform)

	// Scan base image
	baseReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: baseRef,
		Options: &scanv1.ScanOptions{
			Platform: platform,
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE,
			},
		},
	})
	baseResp, err := s.clients.Vulns.Scan(ctx, baseReq)
	if err != nil {
		return nil, DiffRefsResult{}, fmt.Errorf("failed to scan base image %s: %w", baseRef, err)
	}

	// Scan target image
	targetReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: targetRef,
		Options: &scanv1.ScanOptions{
			Platform: platform,
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE,
			},
		},
	})
	targetResp, err := s.clients.Vulns.Scan(ctx, targetReq)
	if err != nil {
		return nil, DiffRefsResult{}, fmt.Errorf("failed to scan target image %s: %w", targetRef, err)
	}

	baseScan := baseResp.Msg
	targetScan := targetResp.Msg

	result := DiffRefsResult{
		BaseRef:              baseRef,
		TargetRef:            targetRef,
		Platform:             platform,
		IsContainerDiff:      true,
		Changes:              make([]DependencyChange, 0),
		VulnerabilitySummary: make(map[string]int),
	}

	// Build package maps for comparison
	basePackages := make(map[string]*PackageInfo)
	for _, pkg := range baseScan.Packages {
		key := diffPackageKey(pkg.Purl, pkg.Ecosystem, pkg.Name)
		basePackages[key] = &PackageInfo{Name: pkg.Name, Version: pkg.Version, Ecosystem: mcpOutputEcosystem(pkg.Ecosystem), PURL: pkg.Purl, Direct: pkg.Direct}
	}

	targetPackages := make(map[string]*PackageInfo)
	for _, pkg := range targetScan.Packages {
		key := diffPackageKey(pkg.Purl, pkg.Ecosystem, pkg.Name)
		targetPackages[key] = &PackageInfo{Name: pkg.Name, Version: pkg.Version, Ecosystem: mcpOutputEcosystem(pkg.Ecosystem), PURL: pkg.Purl, Direct: pkg.Direct}
	}

	// Find added and updated packages
	for key, targetPkg := range targetPackages {
		basePkg, exists := basePackages[key]
		if !exists {
			result.Changes = append(result.Changes, DependencyChange{
				Name:          targetPkg.Name,
				TargetVersion: targetPkg.Version,
				PURL:          targetPkg.PURL,
				ChangeType:    "added",
				IsDirect:      targetPkg.Direct,
				Ecosystem:     targetPkg.Ecosystem,
			})
			result.AddedCount++
		} else if basePkg.Version != targetPkg.Version {
			changeType := "updated"
			if compareVersions(basePkg.Version, targetPkg.Version) < 0 {
				changeType = "upgraded"
			} else {
				changeType = "downgraded"
			}
			result.Changes = append(result.Changes, DependencyChange{
				Name:          targetPkg.Name,
				BaseVersion:   basePkg.Version,
				TargetVersion: targetPkg.Version,
				PURL:          targetPkg.PURL,
				ChangeType:    changeType,
				IsDirect:      targetPkg.Direct,
				Ecosystem:     targetPkg.Ecosystem,
			})
			result.UpdatedCount++
		}
	}

	// Find removed packages
	for key, basePkg := range basePackages {
		if _, exists := targetPackages[key]; !exists {
			result.Changes = append(result.Changes, DependencyChange{
				Name:        basePkg.Name,
				BaseVersion: basePkg.Version,
				PURL:        basePkg.PURL,
				ChangeType:  "removed",
				IsDirect:    basePkg.Direct,
				Ecosystem:   basePkg.Ecosystem,
			})
			result.RemovedCount++
		}
	}

	result.VulnerabilitySummary, result.Vulnerabilities = diffTargetVulnerabilities(targetScan)
	sortDependencyChanges(result.Changes)
	baseInternal := internalproto.ScanningResultFromProto(baseScan)
	targetInternal := internalproto.ScanningResultFromProto(targetScan)
	if baseInternal != nil && targetInternal != nil {
		containerDiff := internalproto.BuildContainerDiffResponseFromScanning(baseInternal, targetInternal)
		result.VulnerabilityChanges = containerVulnerabilityChangesToMCP(containerDiff.GetVulnerabilityChanges())
		result.ContainerSummary = containerSummaryToMCP(containerDiff.GetSummary())
	}

	return nil, result, nil
}

// diffGitRefs compares dependencies between Git references.
func (s *Server) diffGitRefs(ctx context.Context, args DiffRefsInput) (*mcp.CallToolResult, DiffRefsResult, error) {
	if args.Path == "" {
		return nil, DiffRefsResult{}, fmt.Errorf("path is required for Git ref comparison")
	}
	targetPath, err := normalizeLocalPath(args.Path)
	if err != nil {
		return nil, DiffRefsResult{}, err
	}
	baseRef := strings.TrimSpace(args.BaseRef)
	targetRef := strings.TrimSpace(args.TargetRef)

	// Scan base ref
	baseReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: targetPath,
		Options: &scanv1.ScanOptions{
			Ecosystems:   normalizeMCPEcosystems(args.Ecosystems),
			ExcludePaths: s.excludePaths(args.ExcludePaths),
			Ref:          baseRef,
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_GIT,
			},
		},
	})
	baseResp, err := s.clients.Vulns.Scan(ctx, baseReq)
	if err != nil {
		return nil, DiffRefsResult{}, fmt.Errorf("failed to scan base ref %s: %w", baseRef, err)
	}

	// Scan target ref
	targetReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: targetPath,
		Options: &scanv1.ScanOptions{
			Ecosystems:   normalizeMCPEcosystems(args.Ecosystems),
			ExcludePaths: s.excludePaths(args.ExcludePaths),
			Ref:          targetRef,
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_GIT,
			},
		},
	})
	targetResp, err := s.clients.Vulns.Scan(ctx, targetReq)
	if err != nil {
		return nil, DiffRefsResult{}, fmt.Errorf("failed to scan target ref %s: %w", targetRef, err)
	}

	baseScan := baseResp.Msg
	targetScan := targetResp.Msg

	result := DiffRefsResult{
		Path:                 targetPath,
		BaseRef:              baseRef,
		TargetRef:            targetRef,
		BaseCommit:           strings.TrimSpace(baseScan.GetTarget().GetCommitHash()),
		TargetCommit:         strings.TrimSpace(targetScan.GetTarget().GetCommitHash()),
		IsContainerDiff:      false,
		Changes:              make([]DependencyChange, 0),
		VulnerabilitySummary: make(map[string]int),
	}

	// Build package maps for comparison
	basePackages := make(map[string]*PackageInfo)
	for _, pkg := range baseScan.Packages {
		key := diffPackageKey(pkg.Purl, pkg.Ecosystem, pkg.Name)
		basePackages[key] = &PackageInfo{Name: pkg.Name, Version: pkg.Version, Ecosystem: mcpOutputEcosystem(pkg.Ecosystem), PURL: pkg.Purl, Direct: pkg.Direct}
	}

	targetPackages := make(map[string]*PackageInfo)
	for _, pkg := range targetScan.Packages {
		key := diffPackageKey(pkg.Purl, pkg.Ecosystem, pkg.Name)
		targetPackages[key] = &PackageInfo{Name: pkg.Name, Version: pkg.Version, Ecosystem: mcpOutputEcosystem(pkg.Ecosystem), PURL: pkg.Purl, Direct: pkg.Direct}
	}

	// Find added and updated packages
	for key, targetPkg := range targetPackages {
		basePkg, exists := basePackages[key]
		if !exists {
			result.Changes = append(result.Changes, DependencyChange{
				Name:          targetPkg.Name,
				TargetVersion: targetPkg.Version,
				PURL:          targetPkg.PURL,
				ChangeType:    "added",
				IsDirect:      targetPkg.Direct,
				Ecosystem:     targetPkg.Ecosystem,
			})
			result.AddedCount++
		} else if basePkg.Version != targetPkg.Version {
			changeType := "updated"
			if compareVersions(basePkg.Version, targetPkg.Version) < 0 {
				changeType = "upgraded"
			} else {
				changeType = "downgraded"
			}
			result.Changes = append(result.Changes, DependencyChange{
				Name:          targetPkg.Name,
				BaseVersion:   basePkg.Version,
				TargetVersion: targetPkg.Version,
				PURL:          targetPkg.PURL,
				ChangeType:    changeType,
				IsDirect:      targetPkg.Direct,
				Ecosystem:     targetPkg.Ecosystem,
			})
			result.UpdatedCount++
		}
	}

	// Find removed packages
	for key, basePkg := range basePackages {
		if _, exists := targetPackages[key]; !exists {
			result.Changes = append(result.Changes, DependencyChange{
				Name:        basePkg.Name,
				BaseVersion: basePkg.Version,
				PURL:        basePkg.PURL,
				ChangeType:  "removed",
				IsDirect:    basePkg.Direct,
				Ecosystem:   basePkg.Ecosystem,
			})
			result.RemovedCount++
		}
	}

	result.VulnerabilitySummary, result.Vulnerabilities = diffTargetVulnerabilities(targetScan)
	sortDependencyChanges(result.Changes)

	return nil, result, nil
}

var mcpImageSchemes = map[string]struct{}{
	"container":     {},
	"docker":        {},
	"docker-daemon": {},
	"oci":           {},
	"oci-archive":   {},
	"oci-layout":    {},
	"tarball":       {},
}

var mcpKnownGitHosts = map[string]struct{}{
	"bitbucket.org": {},
	"github.com":    {},
	"gitlab.com":    {},
}

var mcpCommonGitRefNames = map[string]struct{}{
	"dev":         {},
	"develop":     {},
	"development": {},
	"head":        {},
	"main":        {},
	"master":      {},
	"trunk":       {},
}

// isContainerDiffInput returns true when diff_refs should compare container images.
func isContainerDiffInput(args DiffRefsInput) bool {
	if isGitRepoPath(args.Path) {
		return looksLikeExplicitContainerImage(args.BaseRef) && looksLikeExplicitContainerImage(args.TargetRef)
	}
	return isContainerImageRef(args.BaseRef) && isContainerImageRef(args.TargetRef)
}

// isMixedContainerRefInput reports whether diff_refs was given one container
// image ref and one Git ref, an unsupported combination the caller rejects.
func isMixedContainerRefInput(args DiffRefsInput) bool {
	baseImage := isContainerImageRef(args.BaseRef)
	targetImage := isContainerImageRef(args.TargetRef)
	if baseImage == targetImage {
		return false
	}
	if strings.TrimSpace(args.Path) == "" {
		return true
	}
	return isExplicitContainerSignal(args.BaseRef) || isExplicitContainerSignal(args.TargetRef)
}

// isGitRepoPath reports whether path is a Git working tree (contains a .git
// entry). Callers must validate path before calling; it performs a filesystem
// stat on the argument.
func isGitRepoPath(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(path, ".git")); err == nil {
		return true
	}
	return false
}

func isExplicitContainerSignal(ref string) bool {
	return isImageTargetScheme(ref) || looksLikeExplicitContainerImage(ref)
}

func isImageTargetScheme(ref string) bool {
	scheme, _, ok := strings.Cut(strings.TrimSpace(ref), "://")
	if !ok {
		return false
	}
	_, ok = mcpImageSchemes[strings.ToLower(scheme)]
	return ok
}

// looksLikeExplicitContainerImage returns true for refs that are unambiguously
// container images even inside a Git repository context.
func looksLikeExplicitContainerImage(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	if strings.Contains(ref, "://") {
		return isImageTargetScheme(ref)
	}
	if hasExplicitTagOrDigest(ref) {
		return true
	}
	host := imageHost(ref)
	return host == "localhost" || strings.Contains(host, ".") || strings.Contains(host, ":")
}

// isContainerImageRef checks if a reference looks like a container image.
func isContainerImageRef(ref string) bool {
	if isImageTargetScheme(ref) {
		return true
	}
	return looksLikeContainerReference(ref)
}

func looksLikeContainerReference(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	if strings.Contains(ref, "://") {
		return false
	}
	if strings.HasPrefix(strings.ToLower(ref), "pkg:") {
		return false
	}
	if strings.HasPrefix(ref, ".") || strings.HasPrefix(ref, "/") {
		return false
	}
	if strings.HasPrefix(ref, "git@") || strings.HasPrefix(ref, "ssh://") {
		return false
	}
	if strings.HasSuffix(ref, ".git") {
		return false
	}
	if strings.ContainsAny(ref, " \t\n") {
		return false
	}
	if looksLikeGitRefName(ref) {
		return false
	}
	if _, err := name.ParseReference(ref, name.WeakValidation); err != nil {
		return false
	}
	if at := strings.Index(ref, "@"); at != -1 {
		if slash := strings.Index(ref, "/"); slash == -1 || at < slash {
			return false
		}
	}

	host := imageHost(ref)
	if host == "" {
		return true
	}
	host = strings.ToLower(host)
	if _, ok := mcpKnownGitHosts[host]; ok {
		return false
	}
	if host == "localhost" || strings.Contains(host, ".") || strings.Contains(host, ":") {
		return true
	}
	return hasExplicitTagOrDigest(ref)
}

func looksLikeGitRefName(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	refLower := strings.ToLower(ref)
	if _, ok := mcpCommonGitRefNames[refLower]; ok {
		return true
	}
	return strings.HasPrefix(refLower, "refs/heads/") ||
		strings.HasPrefix(refLower, "refs/tags/")
}

func imageHost(ref string) string {
	if idx := strings.IndexRune(ref, '/'); idx != -1 {
		return ref[:idx]
	}
	return ""
}

func hasExplicitTagOrDigest(ref string) bool {
	if strings.Contains(ref, "@") {
		return true
	}
	colon := strings.LastIndex(ref, ":")
	if colon == -1 {
		return false
	}
	slash := strings.LastIndex(ref, "/")
	return colon > slash && colon < len(ref)-1
}

// compareVersions compares two version strings.
// Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
func compareVersions(v1, v2 string) int {
	v1Norm := semverComparable(v1)
	v2Norm := semverComparable(v2)
	if semver.IsValid(v1Norm) && semver.IsValid(v2Norm) {
		return semver.Compare(v1Norm, v2Norm)
	}
	if v1 < v2 {
		return -1
	}
	if v1 > v2 {
		return 1
	}
	return 0
}

func semverComparable(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// PackageInfo holds package information for diff comparison.
type PackageInfo struct {
	Name      string
	Version   string
	Ecosystem string
	PURL      string
	Direct    bool
}

func sortDependencyChanges(changes []DependencyChange) {
	slices.SortFunc(changes, compareDependencyChanges)
}

func compareDependencyChanges(a, b DependencyChange) int {
	if a.IsDirect != b.IsDirect {
		if a.IsDirect {
			return -1
		}
		return 1
	}
	if c := cmp.Compare(changeTypeRank(a.ChangeType), changeTypeRank(b.ChangeType)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Ecosystem, b.Ecosystem); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	if c := cmp.Compare(a.PURL, b.PURL); c != 0 {
		return c
	}
	if c := cmp.Compare(a.BaseVersion, b.BaseVersion); c != 0 {
		return c
	}
	return cmp.Compare(a.TargetVersion, b.TargetVersion)
}

func changeTypeRank(changeType string) int {
	switch changeType {
	case "added":
		return 0
	case "removed":
		return 1
	case "upgraded":
		return 2
	case "downgraded":
		return 3
	case "updated":
		return 4
	default:
		return 5
	}
}

func diffPackageKey(purl, ecosystemName, packageName string) string {
	if parsed, err := purlx.ParseLoose(purl); err == nil {
		parsed.Version = ""
		parsed.Subpath = ""
		return "purl:" + parsed.String()
	}
	return fmt.Sprintf("package:%s/%s", normalizeMCPPackageEcosystem(ecosystemName), strings.TrimSpace(packageName))
}

func diffTargetVulnerabilities(scanResult *scanv1.ScanResponse) (map[string]int, []VulnExplanation) {
	summary := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	internalScanResult := internalproto.ScanningResultFromProto(scanResult)
	if internalScanResult == nil {
		return summary, nil
	}

	consolidated := vulnerability.ConsolidateAll(internalScanResult.Findings, internalScanResult.Advisories)
	summary["critical"] = int(consolidated.Stats.GetCritical())
	summary["high"] = int(consolidated.Stats.GetHigh())
	summary["medium"] = int(consolidated.Stats.GetMedium())
	summary["low"] = int(consolidated.Stats.GetLow())
	summary["unknown"] = int(consolidated.Stats.GetUnknown())

	vulns := make([]VulnExplanation, 0, len(consolidated.Vulnerabilities))
	for _, vuln := range consolidated.Vulnerabilities {
		vulns = append(vulns, compactVulnExplanationFromConsolidated(vuln))
	}

	return summary, vulns
}

func containerVulnerabilityChangesToMCP(changes []*diffv1.ContainerVulnerabilityChange) []DiffVulnChange {
	if len(changes) == 0 {
		return nil
	}
	out := make([]DiffVulnChange, 0, len(changes))
	for _, change := range changes {
		if change == nil {
			continue
		}
		out = append(out, DiffVulnChange{
			ID:            change.GetId(),
			Aliases:       slices.Clone(change.GetAliases()),
			ChangeType:    vulnerabilityChangeKindString(change.GetChangeKind()),
			Severity:      severityStringForMCP(change.GetSeverity(), change.GetSeverityType()),
			Package:       change.GetPackageName(),
			Ecosystem:     mcpOutputEcosystem(change.GetEcosystem()),
			BaseVersion:   change.GetBaseVersion(),
			TargetVersion: change.GetTargetVersion(),
			FixedVersions: slices.Clone(change.GetFixedVersions()),
			Summary:       change.GetSummary(),
			Published:     change.GetPublished(),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func containerSummaryToMCP(summary *diffv1.ContainerDiffSummary) *ContainerSummary {
	if summary == nil {
		return nil
	}
	return &ContainerSummary{
		PackagesAdded:          int(summary.GetPackagesAdded()),
		PackagesRemoved:        int(summary.GetPackagesRemoved()),
		PackagesUpgraded:       int(summary.GetPackagesUpgraded()),
		PackagesDowngraded:     int(summary.GetPackagesDowngraded()),
		VulnerabilitiesAdded:   int(summary.GetVulnerabilitiesAdded()),
		VulnerabilitiesRemoved: int(summary.GetVulnerabilitiesRemoved()),
		VulnerabilitiesFixed:   int(summary.GetVulnerabilitiesFixed()),
		LayersAdded:            int(summary.GetLayersAdded()),
		LayersRemoved:          int(summary.GetLayersRemoved()),
		ConfigChanged:          summary.GetConfigChanged(),
	}
}

func vulnerabilityChangeKindString(kind diffv1.VulnerabilityChangeKind) string {
	switch kind {
	case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_ADDED:
		return "added"
	case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_REMOVED:
		return "removed"
	case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_FIXED:
		return "fixed"
	case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_PERSISTED:
		return "persisted"
	default:
		return "unspecified"
	}
}

// === Graph Helper Functions ===

// findMatchingNodes finds nodes matching the query with ranked matching.
func findMatchingNodes(g *graph.Graph, query string) []*graph.Node {
	return graphquery.FindMatchingNodes(g, query)
}

func resolveGraphTargetPURLs(g *graph.Graph, target packageurl.PackageURL) []string {
	return graphquery.ResolveTargetPURLs(g, target)
}

// findBestMatchingNode finds the single best matching node for a query.
func findBestMatchingNode(g *graph.Graph, query string) *graph.Node {
	return graphquery.FindBestMatchingNode(g, query)
}

// === Helper Functions ===

const compactVulnReferenceLimit = 5
const allVulnReferences = -1
const maxMCPVulnerablePaths = 50
const maxMCPPathsToTarget = 20
const maxMCPGraphWhyPaths = 10
const maxMCPGraphWhyShowAllPaths = 100

type vulnExplanationOptions struct {
	includeDetails bool
	referenceLimit int
}

func compactVulnExplanationFromConsolidated(v vulnerability.Consolidated) VulnExplanation {
	return vulnExplanationFromConsolidated(v, vulnExplanationOptions{
		referenceLimit: compactVulnReferenceLimit,
	})
}

func vulnExplanationFromConsolidated(v vulnerability.Consolidated, opts vulnExplanationOptions) VulnExplanation {
	refs, truncated := referencesForMCP(v.References, opts.referenceLimit)
	explanation := VulnExplanation{
		ID:            v.PrimaryID,
		Aliases:       stringsForMCP(v.SecondaryIDs),
		Summary:       v.Summary,
		Severity:      severityStringForMCP(v.Severity, v.SeverityType),
		SeverityType:  strings.TrimSpace(v.SeverityType),
		FixedVersions: stringsForMCP(v.FixedVersions),
		PackageFixes:  packageFixesToMCP(v.PackageFixes),
		ResolvedFix:   fixVerdictToMCP(v.Fix),
		References:    refs,
		Published:     v.Published,
		Modified:      v.Modified,
	}
	if opts.includeDetails {
		explanation.Details = v.Details
	}
	if truncated {
		explanation.ReferenceCount = len(v.References)
		explanation.ReferencesTruncated = true
	}
	return explanation
}

func referencesForMCP(values []string, limit int) ([]string, bool) {
	refs := stringsForMCP(values)
	if limit < 0 || len(refs) <= limit {
		return refs, false
	}
	return refs[:limit], true
}

func packageFixesToMCP(fixes []*vulnerabilityv1.PackageFix) []VulnPackageFix {
	out := make([]VulnPackageFix, 0, len(fixes))
	for _, fix := range fixes {
		if fix == nil {
			continue
		}
		out = append(out, VulnPackageFix{
			Module:        fix.GetModule(),
			Ecosystem:     mcpOutputEcosystem(fix.GetEcosystem()),
			FixedVersions: stringsForMCP(fix.GetFixedVersions()),
		})
	}
	return out
}

func stringsForMCP(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return slices.Clone(values)
}

func referenceLimitForMCP(limit *int) int {
	if limit == nil {
		return allVulnReferences
	}
	return *limit
}

func protoSeverityStringForMCP(sev *vulnerabilityv1.Severity) string {
	if sev == nil {
		return "UNKNOWN"
	}
	if sev.GetLevel() != vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_UNSPECIFIED {
		return internalproto.SeverityLevelString(sev.GetLevel())
	}
	return severityStringForMCP(sev.GetRaw(), sev.GetRawType())
}

func severityStringForMCP(raw, rawType string) string {
	sev := vulnseverity.FromRaw(raw, rawType)
	return internalproto.SeverityLevelString(sev.GetLevel())
}

func fixVerdictToMCP(v *vulnerability.FixVerdict) *VulnFixVerdict {
	if v == nil || v.Status == vulnerability.FixStatusUnknown {
		return nil
	}
	return &VulnFixVerdict{
		Status:       fixStatusString(v.Status),
		Version:      v.Version,
		TargetModule: v.TargetModule,
		Claimed:      v.Claimed,
	}
}

func protoFixVerdictToMCP(v *vulnerabilityv1.FixVerdict) *VulnFixVerdict {
	if v == nil || v.GetStatus() == vulnerabilityv1.FixVerdict_STATUS_UNSPECIFIED {
		return nil
	}
	return &VulnFixVerdict{
		Status:       protoFixStatusString(v.GetStatus()),
		Version:      v.GetVersion(),
		TargetModule: v.GetTargetModule(),
		Claimed:      v.GetClaimed(),
	}
}

func remediationDisposition(v vulnerability.Consolidated) (remediable, migration bool) {
	if v.Fix != nil {
		switch v.Fix.Status {
		case vulnerability.FixStatusInPlace, vulnerability.FixStatusUnverified:
			return v.Fix.Version != "", false
		case vulnerability.FixStatusMigration:
			return v.Fix.Version != "" && v.Fix.TargetModule != "", true
		default:
			return false, false
		}
	}
	return vulnerability.FindBestFixedVersion(v.FixedVersions, v.Version) != "", false
}

func fixStatusString(status vulnerability.FixStatus) string {
	switch status {
	case vulnerability.FixStatusInPlace:
		return "in_place"
	case vulnerability.FixStatusMigration:
		return "migration"
	case vulnerability.FixStatusUnavailable:
		return "unavailable"
	case vulnerability.FixStatusUnverified:
		return "unverified"
	default:
		return "unknown"
	}
}

func protoFixStatusString(status vulnerabilityv1.FixVerdict_Status) string {
	switch status {
	case vulnerabilityv1.FixVerdict_STATUS_IN_PLACE:
		return "in_place"
	case vulnerabilityv1.FixVerdict_STATUS_MIGRATION:
		return "migration"
	case vulnerabilityv1.FixVerdict_STATUS_UNAVAILABLE:
		return "unavailable"
	case vulnerabilityv1.FixVerdict_STATUS_UNVERIFIED:
		return "unverified"
	default:
		return "unknown"
	}
}

// advisoryToExplanation converts a proto Advisory to the MCP VulnExplanation type.
func advisoryToExplanation(advisory *vulnerabilityv1.Advisory, referenceLimit int) VulnExplanation {
	if advisory == nil {
		return VulnExplanation{
			Aliases:       []string{},
			Severity:      "UNKNOWN",
			FixedVersions: []string{},
			PackageFixes:  []VulnPackageFix{},
			References:    []string{},
		}
	}

	refs, truncated := referencesForMCP(advisory.GetReferences(), referenceLimit)
	explanation := VulnExplanation{
		ID:            advisory.GetId(),
		Aliases:       stringsForMCP(advisory.GetAliases()),
		Summary:       advisory.GetSummary(),
		Details:       advisory.GetDetails(),
		FixedVersions: stringsForMCP(advisory.GetFixedVersions()),
		PackageFixes:  packageFixesToMCP(advisory.GetPackageFixes()),
		ResolvedFix:   protoFixVerdictToMCP(advisory.GetResolvedFix()),
		References:    refs,
	}
	if truncated {
		explanation.ReferenceCount = len(advisory.GetReferences())
		explanation.ReferencesTruncated = true
	}

	explanation.Severity = protoSeverityStringForMCP(advisory.GetSeverity())

	// Format timestamps
	if advisory.GetPublished() != nil {
		explanation.Published = advisory.GetPublished().AsTime().Format(time.RFC3339)
	}
	if advisory.GetModified() != nil {
		explanation.Modified = advisory.GetModified().AsTime().Format(time.RFC3339)
	}

	return explanation
}

func graphPathToMCP(path graph.Path) GraphPath {
	return GraphPath{
		Nodes:       pathToStrings(path),
		NodeDetails: pathToNodeDetails(path),
		Depth:       path.Len(),
	}
}

// pathToStrings converts a graph.Path to stable display strings.
func pathToStrings(path graph.Path) []string {
	result := make([]string, len(path))
	for i, node := range path {
		result[i] = graphNodeDisplayName(node)
	}
	return result
}

func pathToNodeDetails(path graph.Path) []GraphPathNode {
	if len(path) == 0 {
		return []GraphPathNode{}
	}
	result := make([]GraphPathNode, len(path))
	for i, node := range path {
		result[i] = graphNodeToMCP(node)
	}
	return result
}

func graphNodeToMCP(node *graph.Node) GraphPathNode {
	if node == nil {
		return GraphPathNode{}
	}
	return GraphPathNode{
		Name:         node.GetName(),
		Version:      node.GetVersion(),
		Ecosystem:    mcpOutputEcosystem(node.GetEcosystem()),
		PURL:         node.GetPurl(),
		Direct:       node.GetDirect(),
		Depth:        int(node.GetDepth()),
		Disconnected: node.GetDepth() == graph.DepthDisconnected,
		ImportStatus: graphImportStatusString(node.GetImportStatus()),
	}
}

func graphNodeDisplayName(node *graph.Node) string {
	if node == nil {
		return ""
	}
	if node.GetVersion() == "" {
		return node.GetName()
	}
	return fmt.Sprintf("%s@%s", node.GetName(), node.GetVersion())
}

func graphImportStatusString(status graphv1.ImportStatus) string {
	switch status {
	case graphv1.ImportStatus_IMPORT_STATUS_IMPORTED:
		return "imported"
	case graphv1.ImportStatus_IMPORT_STATUS_REQUIRED:
		return "required"
	case graphv1.ImportStatus_IMPORT_STATUS_DECLARED:
		return "declared"
	default:
		return ""
	}
}
