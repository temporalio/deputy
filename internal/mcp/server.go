package mcp

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	pathpkg "path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	packageurl "github.com/package-url/packageurl-go"
	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	graphv1 "github.com/temporalio/deputy/gen/deputy/graph/v1"
	listv1 "github.com/temporalio/deputy/gen/deputy/list/v1"
	mcpv1 "github.com/temporalio/deputy/gen/deputy/mcp/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	remediationv1 "github.com/temporalio/deputy/gen/deputy/remediation/v1"
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
	sbomx "github.com/temporalio/deputy/internal/sbom"
	"github.com/temporalio/deputy/internal/services"
	"github.com/temporalio/deputy/internal/version"
	"github.com/temporalio/deputy/internal/vulnerability"
	vulnseverity "github.com/temporalio/deputy/internal/vulnerability/severity"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/mod/semver"
	"google.golang.org/protobuf/proto"
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
// concise: it is injected into the client's context once per session.
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
	"- Sampled outputs (advisory references, graph paths) are capped and set a `*Truncated` flag alongside a full count (e.g. `pathCount` with `pathsTruncated`); check them before assuming a result is complete. Other lists are returned whole. Ordering is deterministic across calls.\n" +
	"- A clean target reports `clean: true`; this is success, not an error.\n" +
	"- Absent fields mean empty, zero, or not applicable: results omit empty lists, zero counts, and optional attributes (no `vulnerabilities` key = none found; no `kind` = ordinary vulnerability). Affirmative answers (`clean`, `found`, `direct`, `hasFix`, `migration`, `executable`, `depth`, `isContainerDiff`) are present whenever they apply, even when false or zero; severity count maps always carry all their keys.\n" +
	"- A package absent from the graph is a normal `found: false` result (with a `matchedNode` when the package is present but has no paths), not an error.\n" +
	"- Scan results include a `coverage` block: `covered` lists (ecosystem, artifact) combinations an advisory source answered for, `uncovered` lists those none could (e.g. container base images). Uncovered means not-checked, not safe. Findings carry `sources` (provenance, e.g. `[\"osv\"]`) and `kind` (`malware` vs vulnerability).\n" +
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

// handleInfo serves server information with the same protojson dialect the
// get_server_info tool uses, so both surfaces share one wire shape.
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	info := s.serverInfo()
	info.Transport = "sse"
	out, err := marshalMCPResult(info)
	if err != nil {
		http.Error(w, "failed to encode server info", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(out)
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
	serverInfoIn, serverInfoOut := mustToolSchemas(
		(&mcpv1.GetServerInfoRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.GetServerInfoResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "get_server_info",
		Description:  "Get Deputy MCP server build, process, and tool metadata",
		InputSchema:  serverInfoIn,
		OutputSchema: serverInfoOut,
	}, closedWorld, s.getServerInfo)

	// Policy discovery tools
	policyIn, policyOut := mustToolSchemas(
		(&mcpv1.ListPolicyEntrypointsRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.ListPolicyEntrypointsResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "list_policy_entrypoints",
		Description:  "List Deputy policy entrypoints, categories, variables, and helpers for authoring CEL policies",
		InputSchema:  policyIn,
		OutputSchema: policyOut,
	}, closedWorld, s.listPolicyEntrypoints)

	// Vulnerability explanation tools
	explainIn, explainOut := mustToolSchemas(
		(&mcpv1.ExplainVulnerabilityRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.VulnExplanation{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "explain_vulnerability",
		Description:  "Get detailed information about a vulnerability by its ID (CVE, GHSA, etc.)",
		InputSchema:  explainIn,
		OutputSchema: explainOut,
	}, openWorld, s.explainVulnerability)

	explainBatchIn, explainBatchOut := mustToolSchemas(
		(&mcpv1.ExplainVulnerabilitiesRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.ExplainVulnerabilitiesResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "explain_vulnerabilities",
		Description:  "Get detailed information about multiple vulnerabilities by their IDs",
		InputSchema:  explainBatchIn,
		OutputSchema: explainBatchOut,
	}, openWorld, s.explainVulnerabilities)

	// Package scanning tools
	scanPkgIn, scanPkgOut := mustToolSchemas(
		(&mcpv1.ScanPackageRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.ScanPackageResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "scan_package",
		Description:  "Check a single package for known vulnerabilities by PURL or by name, version, and ecosystem",
		InputSchema:  scanPkgIn,
		OutputSchema: scanPkgOut,
	}, openWorld, s.scanPackage)

	scanDirIn, scanDirOut := mustToolSchemas(
		(&mcpv1.ScanDirectoryRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.ScanDirectoryResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "scan_directory",
		Description:  "Scan a local directory for vulnerabilities by analyzing dependency manifests (go.mod, package.json, etc.)",
		InputSchema:  scanDirIn,
		OutputSchema: scanDirOut,
	}, openWorld, s.scanDirectory)

	// Dependency tools
	listDepsIn, listDepsOut := mustToolSchemas(
		(&mcpv1.ListDependenciesRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.ListDependenciesResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "list_dependencies",
		Description:  "List all dependencies in a directory, optionally filtering to direct dependencies only",
		InputSchema:  listDepsIn,
		OutputSchema: listDepsOut,
	}, closedWorld, s.listDependencies)

	// SBOM tools
	sbomIn, sbomOut := mustToolSchemas(
		(&mcpv1.GenerateSBOMRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.GenerateSBOMResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "generate_sbom",
		Description:  "Generate a Software Bill of Materials (SBOM) for a local directory or repository checkout",
		InputSchema:  sbomIn,
		OutputSchema: sbomOut,
	}, openWorld, s.generateSBOM)

	// Remediation tools
	remediationIn, remediationOut := mustToolSchemas(
		(&mcpv1.GetRemediationRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.GetRemediationResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "get_remediation",
		Description:  "Get remediation commands for fixing vulnerabilities in a scanned directory",
		InputSchema:  remediationIn,
		OutputSchema: remediationOut,
	}, openWorld, s.getRemediation)

	// Graph analysis tools
	analyzeGraphIn, analyzeGraphOut := mustToolSchemas(
		(&mcpv1.AnalyzeGraphRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.AnalyzeGraphResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "analyze_dependency_graph",
		Description:  "Build dependency graph stats and optionally find paths to a package PURL",
		InputSchema:  analyzeGraphIn,
		OutputSchema: analyzeGraphOut,
	}, openWorld, s.analyzeDependencyGraph)

	graphWhyIn, graphWhyOut := mustToolSchemas(
		(&mcpv1.GraphWhyRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.GraphWhyResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "graph_why",
		Description:  "Show why a package name, name@version, or PURL is in the dependency graph",
		InputSchema:  graphWhyIn,
		OutputSchema: graphWhyOut,
	}, openWorld, s.graphWhy)

	graphNeedsIn, graphNeedsOut := mustToolSchemas(
		(&mcpv1.GraphNeedsRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.GraphNeedsResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "graph_needs",
		Description:  "Show what packages depend on a package name, name@version, or PURL",
		InputSchema:  graphNeedsIn,
		OutputSchema: graphNeedsOut,
	}, openWorld, s.graphNeeds)

	// Triage tools
	triageIn, triageOut := mustToolSchemas(
		(&mcpv1.TriageRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.TriageResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "triage_vulnerabilities",
		Description:  "Prioritize and summarize vulnerabilities by severity, exploitability, and fixability to help focus remediation efforts",
		InputSchema:  triageIn,
		OutputSchema: triageOut,
	}, openWorld, s.triageVulnerabilities)

	// Container scanning tools
	scanImgIn, scanImgOut := mustToolSchemas(
		(&mcpv1.ScanContainerRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.ScanContainerResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "scan_container",
		Description:  "Scan a container image for vulnerabilities. Supports remote registries (nginx:1.25, ghcr.io/owner/app:v1) and local Docker daemon images (docker-daemon://myapp:latest).",
		InputSchema:  scanImgIn,
		OutputSchema: scanImgOut,
	}, openWorld, s.scanContainer)

	// Diff tools
	diffIn, diffOut := mustToolSchemas(
		(&mcpv1.DiffRefsRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.DiffRefsResult{}).ProtoReflect().Descriptor(),
	)
	addReadOnlyTool(s, &mcp.Tool{
		Name:         "diff_refs",
		Description:  "Compare dependencies between Git references (branches, tags, commits) or container images. Shows added, removed, and updated packages with vulnerability analysis.",
		InputSchema:  diffIn,
		OutputSchema: diffOut,
	}, openWorld, s.diffRefs)
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
		// GitHub Actions is not a core SCA ecosystem, so ecosystem.Parse does
		// not recognize it; keep the alias set here.
		return "github-actions", true
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
	// Canonicalize first so every ecosystem alias (including github-actions
	// spellings like "gha") maps consistently to a purl type.
	canonical, _ := canonicalMCPEcosystem(ecosystemName)
	if canonical == "github-actions" {
		return purlx.TypeGitHubActions
	}
	switch ecosystem.Parse(canonical) {
	case ecosystem.Go:
		return "golang"
	case ecosystem.RubyGems:
		return "gem"
	case ecosystem.Packagist:
		return "composer"
	default:
		return strings.ToLower(strings.TrimSpace(canonical))
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

func resolveMCPScanPackageTarget(args *mcpv1.ScanPackageRequest) (mcpScanPackageTarget, error) {
	packageName := strings.TrimSpace(args.GetName())
	versionInput := strings.TrimSpace(args.GetVersion())
	ecosystemInput := strings.TrimSpace(args.GetEcosystem())
	purlInput := strings.TrimSpace(args.GetPurl())

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

// scan_directory's input/output contracts live in deputy.mcp.v1
// (ScanDirectoryRequest/ScanDirectoryResult): the tool schema derives from the
// proto descriptors and the wire is protojson.

// list_dependencies' and generate_sbom's input/output contracts live in
// deputy.mcp.v1 (ListDependenciesRequest/ListDependenciesResult,
// GenerateSBOMRequest/GenerateSBOMResult): the tool schemas derive from the
// proto descriptors and the wire is protojson.

// analyze_dependency_graph's, graph_why's, and graph_needs' input/output
// contracts live in deputy.mcp.v1 (AnalyzeGraphRequest/AnalyzeGraphResult,
// GraphWhyRequest/GraphWhyResult, GraphNeedsRequest/GraphNeedsResult): the
// tool schemas derive from the proto descriptors and the wire is protojson.

// triage_vulnerabilities' and scan_container's input/output contracts live in
// deputy.mcp.v1 (TriageRequest/TriageResult, ScanContainerRequest/
// ScanContainerResult): the tool schemas derive from the proto descriptors and
// the wire is protojson.

// === Tool Implementations ===

func (s *Server) getServerInfo(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "get_server_info", s.toolTimeouts.Default, &mcpv1.GetServerInfoRequest{}, raw, s.getServerInfoTool)
}

// getServerInfoTool reports the running server's build, process, and tool
// metadata.
func (s *Server) getServerInfoTool(context.Context, *mcpv1.GetServerInfoRequest) (proto.Message, error) {
	return s.serverInfo(), nil
}

// serverInfo describes the running server for the get_server_info tool and
// the HTTP /info endpoint.
func (s *Server) serverInfo() *mcpv1.GetServerInfoResult {
	tools := slices.Clone(s.toolNames)
	excludePaths := slices.Clone(s.defaultExcludePaths)
	return &mcpv1.GetServerInfoResult{
		Name:                "deputy",
		Version:             version.Value,
		Protocol:            "mcp",
		Description:         "Deputy MCP server for software supply chain security",
		ProcessId:           int32(os.Getpid()),
		StartedAt:           s.startedAt.Format(time.RFC3339),
		ToolCount:           int32(len(tools)),
		Tools:               tools,
		DefaultExcludePaths: excludePaths,
	}
}

func (s *Server) listPolicyEntrypoints(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "list_policy_entrypoints", s.toolTimeouts.Default, &mcpv1.ListPolicyEntrypointsRequest{}, raw, s.listPolicyEntrypointsTool)
}

// listPolicyEntrypointsTool lists CEL policy entrypoints from the policy service, a thin envelope over deputy.policy.v1.
func (s *Server) listPolicyEntrypointsTool(ctx context.Context, args *mcpv1.ListPolicyEntrypointsRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)

	category := policy.NormalizeCategory(args.GetCategory())
	logs.Debug(ctx, "MCP tool invoked", "tool", "list_policy_entrypoints", "category", category)

	if s.clients.Policy == nil {
		return nil, fmt.Errorf("policy service client is not configured")
	}

	resp, err := s.clients.Policy.ListEntrypoints(ctx, connect.NewRequest(&policyv1.ListEntrypointsRequest{
		Category: category,
	}))
	if err != nil {
		err = fmt.Errorf("list policy entrypoints: %w", err)
		return nil, err
	}

	// The result embeds the policy service's entrypoint metadata directly: the
	// MCP wire is a thin envelope over deputy.policy.v1, not a projection.
	result := &mcpv1.ListPolicyEntrypointsResult{
		Category:        category,
		Entrypoints:     resp.Msg.GetEntrypoints(),
		EntrypointCount: int32(len(resp.Msg.GetEntrypoints())),
	}

	span.SetAttributes(attribute.Int("deputy.mcp.policy_entrypoint_count", int(result.GetEntrypointCount())))
	logs.Debug(ctx, "MCP tool completed", "tool", "list_policy_entrypoints", "category", category, "entrypoints", result.GetEntrypointCount())

	return result, nil
}

func (s *Server) explainVulnerability(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "explain_vulnerability", s.toolTimeouts.Default, &mcpv1.ExplainVulnerabilityRequest{}, raw, s.explainVulnerabilityTool)
}

// explainVulnerabilityTool fetches one advisory and returns its full explanation.
func (s *Server) explainVulnerabilityTool(ctx context.Context, args *mcpv1.ExplainVulnerabilityRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)

	logs.Debug(ctx, "MCP tool invoked", "tool", "explain_vulnerability", "vuln_id", args.GetId())

	vulnID := strings.TrimSpace(args.GetId())
	if vulnID == "" {
		return nil, fmt.Errorf("vulnerability ID is required")
	}

	span.SetAttributes(otel.AttrMCPVulnerabilityID.String(vulnID))

	// Use the VulnerabilityService via clients.Advisory
	advisoryReq := connect.NewRequest(&vulnerabilityv1.GetAdvisoryRequest{
		Id: vulnID,
	})

	resp, err := s.clients.Advisory.GetAdvisory(ctx, advisoryReq)
	if err != nil {
		err = fmt.Errorf("failed to fetch vulnerability %s: %w", vulnID, err)
		logs.Warn(ctx, "Failed to fetch vulnerability", "vuln_id", vulnID, "error", err)
		return nil, err
	}

	if !resp.Msg.GetFound() {
		err = fmt.Errorf("vulnerability %s not found", vulnID)
		return nil, err
	}

	explanation := advisoryExplanationProto(resp.Msg.GetAdvisory(), referenceLimitForMCP(args.ReferenceLimit))

	logs.Debug(ctx, "MCP tool completed", "tool", "explain_vulnerability", "vuln_id", vulnID)

	return explanation, nil
}

func (s *Server) explainVulnerabilities(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "explain_vulnerabilities", s.toolTimeouts.Default, &mcpv1.ExplainVulnerabilitiesRequest{}, raw, s.explainVulnerabilitiesTool)
}

// explainVulnerabilitiesTool fetches several advisories with partial-success semantics: failures are reported per ID in errors.
func (s *Server) explainVulnerabilitiesTool(ctx context.Context, args *mcpv1.ExplainVulnerabilitiesRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)

	logs.Debug(ctx, "MCP tool invoked", "tool", "explain_vulnerabilities", "count", len(args.GetIds()))

	ids, err := normalizeMCPVulnerabilityIDs(args.GetIds())
	if err != nil {
		return nil, err
	}

	span.SetAttributes(otel.AttrMCPVulnerabilityCount.Int(len(ids)))

	uniqueIDs := uniqueMCPVulnerabilityIDs(ids)
	advisoryReq := connect.NewRequest(&vulnerabilityv1.GetAdvisoriesRequest{
		Ids: uniqueIDs,
	})
	resp, err := s.clients.Advisory.GetAdvisories(ctx, advisoryReq)
	if err != nil {
		err = fmt.Errorf("failed to fetch vulnerabilities: %w", err)
		logs.Warn(ctx, "Failed to fetch vulnerabilities", "count", len(uniqueIDs), "error", err)
		return nil, err
	}

	result := &mcpv1.ExplainVulnerabilitiesResult{}

	advisories := resp.Msg.GetAdvisories()
	notFound := stringSet(resp.Msg.GetNotFound())
	errorsByID := resp.Msg.GetErrors()
	for _, id := range ids {
		if advisory := advisoryForMCPVulnerabilityID(advisories, id); advisory != nil {
			result.Vulnerabilities = append(result.Vulnerabilities, advisoryExplanationProto(advisory, referenceLimitForMCP(args.ReferenceLimit)))
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
		// The advisory service answered without listing this ID anywhere; treat
		// it as not found but name the inconsistency for debuggability.
		result.Errors = append(result.Errors, fmt.Sprintf("%s: advisory response missing this ID", id))
	}

	logs.Debug(ctx, "MCP tool completed", "tool", "explain_vulnerabilities", "found", len(result.Vulnerabilities), "errors", len(result.Errors))

	return result, nil
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

func (s *Server) scanPackage(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "scan_package", s.toolTimeouts.Default, &mcpv1.ScanPackageRequest{}, raw, s.scanPackageTool)
}

// scanPackageTool checks one resolved package version for known vulnerabilities.
func (s *Server) scanPackageTool(ctx context.Context, args *mcpv1.ScanPackageRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)

	logs.Debug(ctx, "MCP tool invoked", "tool", "scan_package", "package", args.GetName(), "version", args.GetVersion(), "ecosystem", args.GetEcosystem())

	target, err := resolveMCPScanPackageTarget(args)
	if err != nil {
		return nil, err
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
		logs.Warn(ctx, "Package scan failed", "package", target.packageName, "error", err)
		return nil, err
	}

	result := &mcpv1.ScanPackageResult{
		Package:   target.packageName,
		Version:   target.version,
		Ecosystem: target.ecosystemName,
		Purl:      target.purl,
	}

	scanResult := internalproto.ScanningResultFromProto(resp.Msg)
	consolidated := vulnerability.ConsolidateAll(scanResult.Findings, scanResult.Advisories)
	for _, vuln := range consolidated.Vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, vulnExplanationProto(vuln, vulnExplanationOptions{referenceLimit: compactVulnReferenceLimit}))
	}

	result.Clean = proto.Bool(len(result.Vulnerabilities) == 0)

	span.SetAttributes(otel.AttrMCPVulnerabilityCount.Int(len(result.Vulnerabilities)))
	logs.Debug(ctx, "MCP tool completed", "tool", "scan_package", "package", target.packageName, "vulns", len(result.Vulnerabilities), "clean", result.GetClean())

	return result, nil
}

func (s *Server) scanDirectory(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "scan_directory", s.toolTimeouts.Scan, &mcpv1.ScanDirectoryRequest{}, raw, s.scanDirectoryTool)
}

// scanDirectoryTool scans a local directory and summarizes consolidated findings with advisory-source coverage.
func (s *Server) scanDirectoryTool(ctx context.Context, args *mcpv1.ScanDirectoryRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)
	startTime := time.Now()

	logs.Debug(ctx, "MCP tool invoked", "tool", "scan_directory", "path", args.GetPath())

	// Validate path to prevent path traversal and access to sensitive directories.
	targetPath, err := normalizeLocalPath(args.GetPath())
	if err != nil {
		logs.Warn(ctx, "Invalid path in scan_directory", "path", args.GetPath(), "error", err)
		return nil, err
	}

	span.SetAttributes(otel.AttrTargetPath.String(targetPath))

	// Build proto request
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: targetPath,
		Options: &scanv1.ScanOptions{
			Ref:          strings.TrimSpace(args.GetRef()),
			Ecosystems:   normalizeMCPEcosystems(args.GetEcosystems()),
			ExcludePaths: s.excludePaths(args.GetExcludePaths()),
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_DIR,
			},
		},
	})

	resp, err := s.clients.Vulns.Scan(ctx, scanReq)
	if err != nil {
		err = fmt.Errorf("scan failed: %w", err)
		logs.Warn(ctx, "Directory scan failed", "path", targetPath, "error", err)
		return nil, err
	}

	scanResult := resp.Msg
	internalScanResult := internalproto.ScanningResultFromProto(scanResult)
	consolidated := vulnerability.ConsolidateAll(internalScanResult.Findings, internalScanResult.Advisories)
	ref, effectiveRef, commit := mcpTargetRef(scanResult.GetTarget())
	elapsed := time.Since(startTime)
	result := &mcpv1.ScanDirectoryResult{
		Path:            targetPath,
		Ref:             ref,
		EffectiveRef:    effectiveRef,
		Commit:          commit,
		PackagesScanned: scanResult.GetPackagesScanned(),
		VulnerabilitiesBySeverity: map[string]int32{
			"critical": consolidated.Stats.GetCritical(),
			"high":     consolidated.Stats.GetHigh(),
			"medium":   consolidated.Stats.GetMedium(),
			"low":      consolidated.Stats.GetLow(),
			"unknown":  consolidated.Stats.GetUnknown(),
		},
		Clean:      proto.Bool(consolidated.Stats.GetUnique() == 0),
		Coverage:   coverageProto(scanResult.GetCoverage()),
		ScanTime:   elapsed.String(),
		ScanTimeMs: int32(elapsed.Milliseconds()),
	}

	for _, vuln := range consolidated.Vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, vulnExplanationProto(vuln, vulnExplanationOptions{referenceLimit: compactVulnReferenceLimit}))
	}

	span.SetAttributes(
		otel.AttrMCPPackageCount.Int(int(scanResult.GetPackagesScanned())),
		otel.AttrMCPVulnerabilityCount.Int(int(consolidated.Stats.GetUnique())),
	)
	logs.Debug(ctx, "MCP tool completed", "tool", "scan_directory", "path", targetPath, "packages", result.GetPackagesScanned(), "vulns", consolidated.Stats.GetUnique(), "clean", result.GetClean())

	return result, nil
}

func (s *Server) listDependencies(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "list_dependencies", s.toolTimeouts.Scan, &mcpv1.ListDependenciesRequest{}, raw, s.listDependenciesTool)
}

// listDependenciesTool returns the resolved dependency inventory of a directory.
func (s *Server) listDependenciesTool(ctx context.Context, args *mcpv1.ListDependenciesRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)

	logs.Debug(ctx, "MCP tool invoked", "tool", "list_dependencies", "path", args.GetPath(), "direct_only", args.GetDirectOnly())

	// Validate path to prevent path traversal and access to sensitive directories.
	targetPath, err := normalizeLocalPath(args.GetPath())
	if err != nil {
		logs.Warn(ctx, "Invalid path in list_dependencies", "path", args.GetPath(), "error", err)
		return nil, err
	}

	span.SetAttributes(otel.AttrTargetPath.String(targetPath))

	// Build proto request for ListPackages
	listReq := connect.NewRequest(&listv1.ListPackagesRequest{
		Target: targetPath,
		Options: &listv1.ListOptions{
			Ref:          strings.TrimSpace(args.GetRef()),
			Ecosystems:   normalizeMCPEcosystems(args.GetEcosystems()),
			ExcludePaths: s.excludePaths(args.GetExcludePaths()),
			OnlyDirect:   args.GetDirectOnly(),
		},
	})

	resp, err := s.clients.Packages.ListPackages(ctx, listReq)
	if err != nil {
		err = fmt.Errorf("failed to analyze dependencies: %w", err)
		logs.Warn(ctx, "List dependencies failed", "path", targetPath, "error", err)
		return nil, err
	}

	listResult := resp.Msg
	ref, effectiveRef, commit := mcpTargetRef(listResult.GetTarget())
	result := &mcpv1.ListDependenciesResult{
		Path:                 targetPath,
		Ref:                  ref,
		EffectiveRef:         effectiveRef,
		Commit:               commit,
		Dependencies:         make([]*mcpv1.DependencyInfo, 0, len(listResult.Packages)),
		TotalDiscovered:      listResult.Stats.GetTotalPackages(),
		DirectDiscovered:     listResult.Stats.GetDirectPackages(),
		TransitiveDiscovered: listResult.Stats.GetTransitivePackages(),
	}

	for _, pkg := range listResult.Packages {
		result.Dependencies = append(result.Dependencies, &mcpv1.DependencyInfo{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Ecosystem:    mcpOutputEcosystem(pkg.Ecosystem),
			Direct:       proto.Bool(pkg.Direct),
			Locations:    pkg.Locations,
			Purl:         pkg.Purl,
			ManifestRefs: manifestRefsProto(pkg.GetManifestRefs()),
		})
		result.Total++
		if pkg.Direct {
			result.Direct++
		} else {
			result.Transitive++
		}
	}

	span.SetAttributes(otel.AttrMCPPackageCount.Int(int(result.GetTotalDiscovered())))
	logs.Debug(ctx, "MCP tool completed", "tool", "list_dependencies", "path", targetPath, "returned", result.GetTotal(), "total_discovered", result.GetTotalDiscovered(), "direct", result.GetDirect(), "transitive", result.GetTransitive())

	return result, nil
}

func (s *Server) generateSBOM(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "generate_sbom", s.toolTimeouts.SBOM, &mcpv1.GenerateSBOMRequest{}, raw, s.generateSBOMTool)
}

// generateSBOMTool generates and serializes an SBOM for a directory.
func (s *Server) generateSBOMTool(ctx context.Context, args *mcpv1.GenerateSBOMRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)

	logs.Debug(ctx, "MCP tool invoked", "tool", "generate_sbom", "path", args.GetPath(), "format", args.GetFormat())

	// Validate path to prevent path traversal and access to sensitive directories.
	targetPath, err := normalizeLocalPath(args.GetPath())
	if err != nil {
		logs.Warn(ctx, "Invalid path in generate_sbom", "path", args.GetPath(), "error", err)
		return nil, err
	}

	format, err := flags.NormalizeSBOMOutputFormat(args.GetFormat())
	if err != nil {
		return nil, err
	}

	span.SetAttributes(
		otel.AttrTargetPath.String(targetPath),
		attribute.String("deputy.mcp.sbom_format", format),
	)

	opts := sbomx.Options{
		Ref:            strings.TrimSpace(args.GetRef()),
		Ecosystems:     normalizeMCPEcosystems(args.GetEcosystems()),
		ExcludePaths:   s.excludePaths(args.GetExcludePaths()),
		EnrichLicenses: args.GetEnrichLicenses(),
		LicenseSource:  "depsdev",
	}

	sbomResult, err := sbomx.Generate(ctx, targetPath, opts)
	if err != nil {
		err = fmt.Errorf("failed to generate SBOM: %w", err)
		logs.Warn(ctx, "SBOM generation failed", "path", targetPath, "error", err)
		return nil, err
	}

	// Serialize to requested format
	var sb strings.Builder
	switch format {
	case "cyclonedx-json":
		if err := sbomx.WriteCycloneDXJSON(sbomResult.Document, &sb); err != nil {
			err = fmt.Errorf("failed to serialize SBOM: %w", err)
			return nil, err
		}
	case "spdx-json":
		if err := sbomx.WriteSPDXJSON(sbomResult.Document, &sb); err != nil {
			err = fmt.Errorf("failed to serialize SBOM: %w", err)
			return nil, err
		}
	case "protobom-json":
		if err := sbomx.WriteProtobomJSON(sbomResult.Document, &sb); err != nil {
			err = fmt.Errorf("failed to serialize SBOM: %w", err)
			return nil, err
		}
	}

	components := 0
	if sbomResult.Document != nil && sbomResult.Document.NodeList != nil {
		components = len(sbomResult.Document.NodeList.Nodes)
	}

	span.SetAttributes(otel.AttrMCPPackageCount.Int(components))
	logs.Debug(ctx, "MCP tool completed", "tool", "generate_sbom", "path", targetPath, "format", format, "components", components)

	return &mcpv1.GenerateSBOMResult{
		Path:         targetPath,
		Ref:          strings.TrimSpace(sbomResult.Ref),
		EffectiveRef: strings.TrimSpace(sbomResult.Target.EffectiveRef),
		Commit:       strings.TrimSpace(sbomResult.Commit),
		Format:       format,
		Components:   int32(components),
		Sbom:         sb.String(),
	}, nil
}

func (s *Server) getRemediation(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "get_remediation", s.toolTimeouts.Scan, &mcpv1.GetRemediationRequest{}, raw, s.getRemediationTool)
}

// getRemediationTool scans a directory and projects the remediation service's plan for its findings.
func (s *Server) getRemediationTool(ctx context.Context, args *mcpv1.GetRemediationRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)

	logs.Debug(ctx, "MCP tool invoked", "tool", "get_remediation", "path", args.GetPath())

	// Validate path to prevent path traversal and access to sensitive directories.
	targetPath, err := normalizeLocalPath(args.GetPath())
	if err != nil {
		logs.Warn(ctx, "Invalid path in get_remediation", "path", args.GetPath(), "error", err)
		return nil, err
	}

	span.SetAttributes(otel.AttrTargetPath.String(targetPath))

	if s.clients.Remediation == nil {
		return nil, fmt.Errorf("remediation service client is not configured")
	}

	// Build proto request
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: targetPath,
		Options: &scanv1.ScanOptions{
			Ref:          strings.TrimSpace(args.GetRef()),
			Ecosystems:   normalizeMCPEcosystems(args.GetEcosystems()),
			ExcludePaths: s.excludePaths(args.GetExcludePaths()),
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_DIR,
			},
		},
	})

	resp, err := s.clients.Vulns.Scan(ctx, scanReq)
	if err != nil {
		err = fmt.Errorf("scan failed: %w", err)
		logs.Warn(ctx, "Remediation scan failed", "path", targetPath, "error", err)
		return nil, err
	}

	// Generate the plan through the remediation service, the same producer
	// the API and agent flows use, with hints adapted to MCP tooling.
	planResp, err := s.clients.Remediation.GeneratePlan(ctx, connect.NewRequest(&remediationv1.GeneratePlanRequest{
		Source: &remediationv1.GeneratePlanRequest_ScanResult{ScanResult: resp.Msg},
		Options: &remediationv1.PlanOptions{
			GuidanceProfile: remediationv1.GuidanceProfile_GUIDANCE_PROFILE_MCP,
		},
	}))
	if err != nil {
		err = fmt.Errorf("generate remediation plan: %w", err)
		logs.Warn(ctx, "Remediation plan generation failed", "path", targetPath, "error", err)
		return nil, err
	}

	plan := planResp.Msg.GetPlan()
	ref, effectiveRef, commit := mcpTargetRef(resp.Msg.GetTarget())
	result := &mcpv1.GetRemediationResult{
		Path:                     targetPath,
		Ref:                      ref,
		EffectiveRef:             effectiveRef,
		Commit:                   commit,
		PlanId:                   plan.GetId(),
		VulnerabilitiesFound:     resp.Msg.GetStats().GetUnique(),
		Stats:                    planResp.Msg.GetStats(),
		StdlibUpgrade:            plan.GetStdlibUpgrade(),
		UnfixableVulnerabilities: planResp.Msg.GetUnaddressedVulnerabilities(),
	}
	if generated := plan.GetGeneratedAt(); generated != nil {
		result.GeneratedAt = generated.AsTime().Format(time.RFC3339)
	}
	for _, step := range plan.GetSteps() {
		result.Steps = append(result.Steps, remediationStepProto(step))
	}

	span.SetAttributes(
		otel.AttrMCPVulnerabilityCount.Int(int(result.GetVulnerabilitiesFound())),
		attribute.Int("deputy.mcp.remediable_count", int(result.GetStats().GetVulnerabilitiesAddressed())),
		attribute.Int("deputy.mcp.command_count", len(result.GetSteps())),
	)
	logs.Debug(ctx, "MCP tool completed", "tool", "get_remediation", "path", targetPath, "vulns", result.GetVulnerabilitiesFound(), "steps", len(result.GetSteps()), "unfixable", len(result.GetUnfixableVulnerabilities()))

	return result, nil
}

func (s *Server) analyzeDependencyGraph(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "analyze_dependency_graph", s.toolTimeouts.Graph, &mcpv1.AnalyzeGraphRequest{}, raw, s.analyzeDependencyGraphTool)
}

// analyzeDependencyGraphTool reports graph statistics, vulnerable paths, and optional target path resolution.
func (s *Server) analyzeDependencyGraphTool(ctx context.Context, args *mcpv1.AnalyzeGraphRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)

	logs.Debug(ctx, "MCP tool invoked", "tool", "analyze_dependency_graph", "path", args.GetPath(), "target_purl", args.GetTargetPurl())

	if args.GetPath() == "" {
		return nil, fmt.Errorf("path is required")
	}
	targetPath, err := normalizeLocalPath(args.GetPath())
	if err != nil {
		logs.Warn(ctx, "Invalid path in analyze_dependency_graph", "path", args.GetPath(), "error", err)
		return nil, err
	}
	targetPURL := strings.TrimSpace(args.GetTargetPurl())
	var parsedTargetPURL packageurl.PackageURL
	hasTargetPURL := false
	if targetPURL != "" {
		parsed, err := purlx.ParseLoose(targetPURL)
		if err != nil {
			err = fmt.Errorf("targetPurl must be a valid PURL: %w", err)
			return nil, err
		}
		parsedTargetPURL = parsed
		hasTargetPURL = true
	}

	span.SetAttributes(otel.AttrTargetPath.String(targetPath))

	depGraph, target, err := s.buildDependencyGraph(ctx, targetPath, args.GetRef(), args.GetEcosystems(), args.GetExcludePaths(), args.GetResolveTransitives(), args.GetExtended())
	if err != nil {
		logs.Warn(ctx, "Graph analysis failed", "path", targetPath, "error", err)
		return nil, err
	}
	if err := s.annotateGraphVulnerabilities(ctx, targetPath, args.GetRef(), args.GetEcosystems(), args.GetExcludePaths(), depGraph); err != nil {
		err = fmt.Errorf("scan failed: %w", err)
		logs.Warn(ctx, "Graph vulnerability annotation failed", "path", targetPath, "error", err)
		return nil, err
	}

	ref, effectiveRef, commit := mcpTargetRef(target)
	result := &mcpv1.AnalyzeGraphResult{
		Path:         targetPath,
		Ref:          ref,
		EffectiveRef: effectiveRef,
		Commit:       commit,
	}

	// Get stats
	result.Stats = mcpGraphStats(depGraph.Stats())

	// Find vulnerable paths
	vulnPaths := depGraph.VulnerablePaths()
	result.VulnerablePathCount = int32(len(vulnPaths))
	result.VulnerablePathsTruncated = len(vulnPaths) > maxMCPVulnerablePaths
	result.VulnerablePaths = make([]*mcpv1.GraphPath, 0, min(len(vulnPaths), maxMCPVulnerablePaths))
	for _, path := range vulnPaths {
		if len(result.VulnerablePaths) >= maxMCPVulnerablePaths {
			break
		}
		result.VulnerablePaths = append(result.VulnerablePaths, graphPathProto(path))
	}

	// If a target PURL is specified, find paths to matching graph nodes.
	if hasTargetPURL {
		resolvedPURLs := resolveGraphTargetPURLs(depGraph, parsedTargetPURL)
		result.Target = &mcpv1.GraphTargetResult{
			Query:        targetPURL,
			Found:        proto.Bool(len(resolvedPURLs) > 0),
			MatchedPurls: append([]string{}, resolvedPURLs...),
		}
		for _, resolvedPURL := range resolvedPURLs {
			if node := depGraph.Node(resolvedPURL); node != nil {
				result.Target.MatchedNodes = append(result.Target.MatchedNodes, graphNodeProto(node))
			}
			paths := depGraph.PathsTo(resolvedPURL)
			result.Target.PathCount += int32(len(paths))
			for _, path := range paths {
				if len(result.PathsToTarget) >= maxMCPPathsToTarget {
					break
				}
				result.PathsToTarget = append(result.PathsToTarget, graphPathProto(path))
			}
		}
		result.PathsToTargetTruncated = int(result.Target.GetPathCount()) > len(result.PathsToTarget)
		result.Target.Message = graphTargetMessage(result.Target)
	}

	span.SetAttributes(
		otel.AttrMCPPackageCount.Int(int(result.GetStats().GetTotalNodes())),
		attribute.Int("deputy.mcp.vulnerable_nodes", int(result.GetStats().GetVulnerableNodes())),
		otel.AttrMCPGraphPathCount.Int(len(result.GetVulnerablePaths())),
	)
	logs.Debug(ctx, "MCP tool completed", "tool", "analyze_dependency_graph", "path", targetPath, "nodes", result.GetStats().GetTotalNodes(), "vulnerable_nodes", result.GetStats().GetVulnerableNodes())

	return result, nil
}

// graphTargetMessage summarizes a targetPurl query outcome in one sentence,
// distinguishing not-found from present-but-pathless. Returns "" for a nil
// target so the message field is omitted when no targetPurl was requested.
func graphTargetMessage(target *mcpv1.GraphTargetResult) string {
	switch {
	case target == nil:
		return ""
	case !target.GetFound():
		return "Target PURL was not found in the dependency graph"
	case target.GetPathCount() == 0:
		return "Target PURL is present in the dependency graph, but no dependency path from a direct/root dependency was resolved"
	case target.GetPathCount() == 1:
		return "1 dependency path to target found"
	default:
		return fmt.Sprintf("%d dependency paths to target found", target.GetPathCount())
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

// mcpGraphStats rebuilds graph stats for the MCP result: ecosystem keys are
// normalized to their canonical output names (merging counts that collapse to
// the same name); everything else carries over unchanged.
func mcpGraphStats(stats *graphv1.GraphStats) *graphv1.GraphStats {
	ecosystems := make(map[string]int32, len(stats.GetEcosystems()))
	for k, v := range stats.GetEcosystems() {
		ecosystems[mcpOutputEcosystem(k)] += v
	}
	return &graphv1.GraphStats{
		TotalNodes:         stats.GetTotalNodes(),
		DirectNodes:        stats.GetDirectNodes(),
		TransitiveNodes:    stats.GetTransitiveNodes(),
		MaxDepth:           stats.GetMaxDepth(),
		MaxConnectedDepth:  stats.GetMaxConnectedDepth(),
		DisconnectedNodes:  stats.GetDisconnectedNodes(),
		VulnerableNodes:    stats.GetVulnerableNodes(),
		Ecosystems:         ecosystems,
		ImportStatusCounts: stats.GetImportStatusCounts(),
	}
}

// === Graph, Triage, and Container Tool Implementations ===

func (s *Server) graphWhy(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "graph_why", s.toolTimeouts.Graph, &mcpv1.GraphWhyRequest{}, raw, s.graphWhyTool)
}

// graphWhyTool traces why a package is present in the dependency graph.
func (s *Server) graphWhyTool(ctx context.Context, args *mcpv1.GraphWhyRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)

	logs.Debug(ctx, "MCP tool invoked", "tool", "graph_why", "path", args.GetPath(), "package", args.GetPackage())

	packageQuery := strings.TrimSpace(args.GetPackage())

	// Validate path to prevent path traversal and access to sensitive directories.
	targetPath, err := normalizeLocalPath(args.GetPath())
	if err != nil {
		logs.Warn(ctx, "Invalid path in graph_why", "path", args.GetPath(), "error", err)
		return nil, err
	}
	if packageQuery == "" {
		return nil, fmt.Errorf("package name is required")
	}

	span.SetAttributes(
		otel.AttrTargetPath.String(targetPath),
		otel.AttrMCPGraphPackage.String(packageQuery),
	)

	depGraph, target, err := s.buildDependencyGraph(ctx, targetPath, args.GetRef(), args.GetEcosystems(), args.GetExcludePaths(), args.GetResolveTransitives(), args.GetExtended())
	if err != nil {
		logs.Warn(ctx, "Graph why failed", "path", targetPath, "package", packageQuery, "error", err)
		return nil, err
	}
	ref, effectiveRef, commit := mcpTargetRef(target)

	// Find matching nodes using ranked matching
	matches := findMatchingNodes(depGraph, packageQuery)
	if len(matches) == 0 {
		span.SetAttributes(otel.AttrMCPGraphFound.Bool(false))
		logs.Debug(ctx, "MCP tool completed", "tool", "graph_why", "package", packageQuery, "found", false)
		return &mcpv1.GraphWhyResult{
			Package:      packageQuery,
			Path:         targetPath,
			Ref:          ref,
			EffectiveRef: effectiveRef,
			Commit:       commit,
			Found:        proto.Bool(false),
			Message:      fmt.Sprintf("Package %q not found in dependency graph", packageQuery),
		}, nil
	}

	// Use the best match
	match := matches[0]
	result := &mcpv1.GraphWhyResult{
		Package:      match.Name,
		Path:         targetPath,
		Version:      match.Version,
		Purl:         match.Purl,
		Ref:          ref,
		EffectiveRef: effectiveRef,
		Commit:       commit,
		Direct:       proto.Bool(match.Direct),
		Found:        proto.Bool(true),
		MatchedNode:  graphNodeProto(match),
	}

	// Return direct dependencies as a one-node path so agents can consume
	// direct and transitive graph answers with the same structured shape.
	if match.Direct {
		result.Paths = []*mcpv1.GraphPath{graphPathProto(graph.Path{match})}
		result.PathCount = 1
		result.Message = "Direct dependency"
		span.SetAttributes(
			otel.AttrMCPGraphFound.Bool(true),
			otel.AttrMCPGraphDirect.Bool(true),
			otel.AttrMCPGraphPathCount.Int(int(result.GetPathCount())),
		)
		logs.Debug(ctx, "MCP tool completed", "tool", "graph_why", "package", packageQuery, "found", true, "direct", true, "paths", result.GetPathCount())
		return result, nil
	}

	// Find paths to the package
	paths := depGraph.PathsTo(match.Purl)
	if len(paths) == 0 {
		result.Message = graphquery.NoDependencyPathMessage(match, args.GetResolveTransitives(), args.GetExtended())
		span.SetAttributes(
			otel.AttrMCPGraphFound.Bool(true),
			otel.AttrMCPGraphPathCount.Int(0),
		)
		logs.Debug(ctx, "MCP tool completed", "tool", "graph_why", "package", packageQuery, "found", true, "paths", 0)
		return result, nil
	}

	// Convert paths
	limit := maxMCPGraphWhyPaths
	if args.GetShowAll() {
		limit = maxMCPGraphWhyShowAllPaths
	}
	result.Paths = make([]*mcpv1.GraphPath, 0, min(len(paths), limit))
	for i, path := range paths {
		if i >= limit {
			break
		}
		result.Paths = append(result.Paths, graphPathProto(path))
	}
	result.PathCount = int32(len(paths))
	result.PathsTruncated = len(paths) > limit

	if len(paths) == 1 {
		result.Message = "1 dependency path found"
	} else {
		result.Message = fmt.Sprintf("%d dependency paths found", len(paths))
	}

	span.SetAttributes(
		otel.AttrMCPGraphFound.Bool(true),
		otel.AttrMCPGraphDirect.Bool(false),
		otel.AttrMCPGraphPathCount.Int(int(result.GetPathCount())),
	)
	logs.Debug(ctx, "MCP tool completed", "tool", "graph_why", "package", packageQuery, "found", true, "paths", result.GetPathCount())

	return result, nil
}

func (s *Server) graphNeeds(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "graph_needs", s.toolTimeouts.Graph, &mcpv1.GraphNeedsRequest{}, raw, s.graphNeedsTool)
}

// graphNeedsTool lists the packages that depend on a package.
func (s *Server) graphNeedsTool(ctx context.Context, args *mcpv1.GraphNeedsRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)

	logs.Debug(ctx, "MCP tool invoked", "tool", "graph_needs", "path", args.GetPath(), "package", args.GetPackage())

	packageQuery := strings.TrimSpace(args.GetPackage())

	// Validate path to prevent path traversal and access to sensitive directories.
	targetPath, err := normalizeLocalPath(args.GetPath())
	if err != nil {
		logs.Warn(ctx, "Invalid path in graph_needs", "path", args.GetPath(), "error", err)
		return nil, err
	}
	if packageQuery == "" {
		return nil, fmt.Errorf("package name is required")
	}

	span.SetAttributes(
		otel.AttrTargetPath.String(targetPath),
		otel.AttrMCPGraphPackage.String(packageQuery),
	)

	depGraph, target, err := s.buildDependencyGraph(ctx, targetPath, args.GetRef(), args.GetEcosystems(), args.GetExcludePaths(), args.GetResolveTransitives(), args.GetExtended())
	if err != nil {
		logs.Warn(ctx, "Graph needs failed", "path", targetPath, "package", packageQuery, "error", err)
		return nil, err
	}
	ref, effectiveRef, commit := mcpTargetRef(target)

	// Find best matching node
	match := findBestMatchingNode(depGraph, packageQuery)
	if match == nil {
		span.SetAttributes(otel.AttrMCPGraphFound.Bool(false))
		logs.Debug(ctx, "MCP tool completed", "tool", "graph_needs", "package", packageQuery, "found", false)
		return &mcpv1.GraphNeedsResult{
			Package:      packageQuery,
			Path:         targetPath,
			Ref:          ref,
			EffectiveRef: effectiveRef,
			Commit:       commit,
			Found:        proto.Bool(false),
			Message:      fmt.Sprintf("Package %q not found in dependency graph", packageQuery),
		}, nil
	}

	result := &mcpv1.GraphNeedsResult{
		Package:      match.Name,
		Path:         targetPath,
		Version:      match.Version,
		Purl:         match.Purl,
		Ref:          ref,
		EffectiveRef: effectiveRef,
		Commit:       commit,
		Direct:       proto.Bool(match.Direct),
		Found:        proto.Bool(true),
		MatchedNode:  graphNodeProto(match),
	}

	// Collect ancestors (packages that depend on this one). Ancestors is a BFS
	// over the same parent index a direct Parents() call would use, so an empty
	// result here means the node genuinely has no dependents (e.g. a root/direct
	// dependency); NoDependentsMessage explains that case below.
	var directCount, transitiveCount int32
	for ancestor := range depGraph.Ancestors(match.Purl) {
		result.Dependents = append(result.Dependents, &mcpv1.DependencyInfo{
			Name:      ancestor.Name,
			Version:   ancestor.Version,
			Ecosystem: mcpOutputEcosystem(ancestor.Ecosystem),
			Purl:      ancestor.Purl,
			Direct:    proto.Bool(ancestor.Direct),
			Locations: ancestor.Locations,
		})
		if ancestor.Direct {
			directCount++
		} else {
			transitiveCount++
		}
	}
	result.DirectCount = proto.Int32(directCount)
	result.TransitiveCount = proto.Int32(transitiveCount)

	if len(result.Dependents) == 0 {
		result.Message = graphquery.NoDependentsMessage(match, args.GetResolveTransitives())
	}
	sortDependencyInfos(result.Dependents)

	span.SetAttributes(
		otel.AttrMCPGraphFound.Bool(true),
		attribute.Int("deputy.mcp.dependent_count", len(result.Dependents)),
	)
	logs.Debug(ctx, "MCP tool completed", "tool", "graph_needs", "package", packageQuery, "found", true, "dependents", len(result.Dependents))

	return result, nil
}

// sortDependencyInfos orders dependents deterministically: direct dependencies
// first, then by name, then by PURL.
func sortDependencyInfos(deps []*mcpv1.DependencyInfo) {
	slices.SortFunc(deps, func(a, b *mcpv1.DependencyInfo) int {
		if a.GetDirect() != b.GetDirect() {
			if a.GetDirect() {
				return -1
			}
			return 1
		}
		if c := strings.Compare(a.GetName(), b.GetName()); c != 0 {
			return c
		}
		return strings.Compare(a.GetPurl(), b.GetPurl())
	})
}

func (s *Server) triageVulnerabilities(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "triage_vulnerabilities", s.toolTimeouts.Scan, &mcpv1.TriageRequest{}, raw, s.triageVulnerabilitiesTool)
}

// triageVulnerabilitiesTool scans a directory and ranks findings by the canonical triage ladder.
func (s *Server) triageVulnerabilitiesTool(ctx context.Context, args *mcpv1.TriageRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)

	logs.Debug(ctx, "MCP tool invoked", "tool", "triage_vulnerabilities", "path", args.GetPath())

	if args.GetPath() == "" {
		return nil, fmt.Errorf("path is required")
	}
	targetPath, err := normalizeLocalPath(args.GetPath())
	if err != nil {
		logs.Warn(ctx, "Invalid path in triage_vulnerabilities", "path", args.GetPath(), "error", err)
		return nil, err
	}

	span.SetAttributes(otel.AttrTargetPath.String(targetPath))

	// Build proto request
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: targetPath,
		Options: &scanv1.ScanOptions{
			Ref:          strings.TrimSpace(args.GetRef()),
			Ecosystems:   normalizeMCPEcosystems(args.GetEcosystems()),
			ExcludePaths: s.excludePaths(args.GetExcludePaths()),
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_DIR,
			},
		},
	})

	resp, err := s.clients.Vulns.Scan(ctx, scanReq)
	if err != nil {
		err = fmt.Errorf("scan failed: %w", err)
		logs.Warn(ctx, "Triage scan failed", "path", targetPath, "error", err)
		return nil, err
	}

	// Convert proto response to internal types
	scanResult := internalproto.ScanningResultFromProto(resp.Msg)
	ref, effectiveRef, commit := mcpTargetRef(resp.Msg.GetTarget())

	result := &mcpv1.TriageResult{
		Path:         targetPath,
		Ref:          ref,
		EffectiveRef: effectiveRef,
		Commit:       commit,
	}

	// Consolidate vulnerabilities
	consolidated := vulnerability.ConsolidateAll(scanResult.Findings, scanResult.Advisories)

	// Process each vulnerability
	for _, v := range consolidated.Vulnerabilities {
		hasFix, migration := vulnerability.RemediationDisposition(v)
		severity := severityStringForMCP(v.Severity, v.SeverityType)

		// Determine priority based on severity, fixability, and direct dependency
		priority, reason := vulnerability.TriagePriority(severity, hasFix, v.IsDirect)

		triaged := &mcpv1.TriagedVuln{
			Id:             v.PrimaryID,
			Kind:           mcpFindingKind(v.Kind),
			Severity:       severity,
			SeverityType:   strings.TrimSpace(v.SeverityType),
			Sources:        stringsForMCP(v.Sources),
			Package:        v.Package,
			Version:        v.Version,
			Purl:           v.PURL,
			Direct:         proto.Bool(v.IsDirect),
			HasFix:         proto.Bool(hasFix),
			FixedVersions:  stringsForMCP(v.FixedVersions),
			PackageFixes:   packageFixesProto(v.PackageFixes),
			ResolvedFix:    fixVerdictProto(v.Fix),
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

	result.TotalVulnerabilities = int32(len(consolidated.Vulnerabilities))

	// Sort by priority (critical first)
	sortTriagedVulns(result.Vulnerabilities)

	// Generate recommendations
	result.Recommendations = generateRecommendations(result)

	span.SetAttributes(
		otel.AttrMCPTriageCount.Int(int(result.GetTotalVulnerabilities())),
		attribute.Int("deputy.mcp.critical_count", int(result.GetCriticalCount())),
		attribute.Int("deputy.mcp.fixable_count", int(result.GetFixableCount())),
	)
	logs.Debug(ctx, "MCP tool completed", "tool", "triage_vulnerabilities", "path", targetPath, "total", result.GetTotalVulnerabilities(), "critical", result.GetCriticalCount(), "fixable", result.GetFixableCount())

	return result, nil
}

// sortTriagedVulns sorts vulnerabilities by priority, breaking ties on ID so
// the ordering is deterministic for agents diffing successive triage results.
func sortTriagedVulns(vulns []*mcpv1.TriagedVuln) {
	slices.SortFunc(vulns, func(a, b *mcpv1.TriagedVuln) int {
		if c := cmp.Compare(vulnerability.TriagePriorityRank(a.GetPriority()), vulnerability.TriagePriorityRank(b.GetPriority())); c != 0 {
			return c
		}
		return strings.Compare(a.GetId(), b.GetId())
	})
}

// generateRecommendations creates actionable recommendations from triage results.
func generateRecommendations(result *mcpv1.TriageResult) []string {
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

func (s *Server) scanContainer(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "scan_container", s.toolTimeouts.Scan, &mcpv1.ScanContainerRequest{}, raw, s.scanContainerTool)
}

// scanContainerTool scans a container image and summarizes consolidated findings with coverage.
func (s *Server) scanContainerTool(ctx context.Context, args *mcpv1.ScanContainerRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)
	startTime := time.Now()

	logs.Debug(ctx, "MCP tool invoked", "tool", "scan_container", "image", args.GetImage(), "platform", args.GetPlatform())

	imageRef := strings.TrimSpace(args.GetImage())
	if imageRef == "" {
		return nil, fmt.Errorf("image is required")
	}
	platform := strings.TrimSpace(args.GetPlatform())

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
		logs.Warn(ctx, "Container scan failed", "image", imageRef, "error", err)
		return nil, err
	}

	scanResult := resp.Msg
	internalScanResult := internalproto.ScanningResultFromProto(scanResult)
	consolidated := vulnerability.ConsolidateAll(internalScanResult.Findings, internalScanResult.Advisories)
	elapsed := time.Since(startTime)
	result := &mcpv1.ScanContainerResult{
		Image:           imageRef,
		Platform:        platform,
		PackagesScanned: scanResult.GetPackagesScanned(),
		VulnerabilitiesBySeverity: map[string]int32{
			"critical": consolidated.Stats.GetCritical(),
			"high":     consolidated.Stats.GetHigh(),
			"medium":   consolidated.Stats.GetMedium(),
			"low":      consolidated.Stats.GetLow(),
			"unknown":  consolidated.Stats.GetUnknown(),
		},
		Clean:      proto.Bool(consolidated.Stats.GetUnique() == 0),
		Coverage:   coverageProto(scanResult.GetCoverage()),
		ScanTime:   elapsed.String(),
		ScanTimeMs: int32(elapsed.Milliseconds()),
	}

	for _, vuln := range consolidated.Vulnerabilities {
		result.Vulnerabilities = append(result.Vulnerabilities, vulnExplanationProto(vuln, vulnExplanationOptions{referenceLimit: compactVulnReferenceLimit}))
	}

	span.SetAttributes(
		otel.AttrMCPPackageCount.Int(int(scanResult.GetPackagesScanned())),
		otel.AttrMCPVulnerabilityCount.Int(int(consolidated.Stats.GetUnique())),
	)
	logs.Debug(ctx, "MCP tool completed", "tool", "scan_container", "image", imageRef, "packages", result.GetPackagesScanned(), "vulns", consolidated.Stats.GetUnique(), "clean", result.GetClean())

	return result, nil
}

func (s *Server) diffRefs(ctx context.Context, req *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, json.RawMessage, error) {
	return runTool(ctx, s, "diff_refs", s.toolTimeouts.Scan, &mcpv1.DiffRefsRequest{}, raw, s.diffRefsTool)
}

// diffRefsTool compares dependencies between two Git refs or two container images.
func (s *Server) diffRefsTool(ctx context.Context, args *mcpv1.DiffRefsRequest) (proto.Message, error) {
	span := otel.SpanFromContext(ctx)

	logs.Debug(ctx, "MCP tool invoked", "tool", "diff_refs", "base_ref", args.GetBaseRef(), "target_ref", args.GetTargetRef())

	// Normalize into a fresh request rather than mutating the parsed message:
	// the routing helpers and both diff paths read the trimmed values.
	args = &mcpv1.DiffRefsRequest{
		Path:         strings.TrimSpace(args.GetPath()),
		BaseRef:      strings.TrimSpace(args.GetBaseRef()),
		TargetRef:    strings.TrimSpace(args.GetTargetRef()),
		Platform:     strings.TrimSpace(args.GetPlatform()),
		Ecosystems:   args.GetEcosystems(),
		ExcludePaths: args.GetExcludePaths(),
	}

	span.SetAttributes(
		otel.AttrMCPBaseRef.String(args.GetBaseRef()),
		otel.AttrMCPTargetRef.String(args.GetTargetRef()),
	)

	// Validate the path before routing. Routing calls os.Stat on the path to
	// detect a Git working tree, so validate first to avoid probing the
	// filesystem with an unvalidated (e.g. traversal) path.
	if args.GetPath() != "" {
		if _, err := normalizeLocalPath(args.GetPath()); err != nil {
			err = fmt.Errorf("invalid path: %w", err)
			return nil, err
		}
	}

	if isMixedContainerRefInput(args) {
		return nil, fmt.Errorf("baseRef and targetRef must both be Git refs or both be container image refs")
	}

	// Check if this looks like a container image diff.
	isContainerDiff := isContainerDiffInput(args)

	var result *mcpv1.DiffRefsResult
	var err error
	if isContainerDiff {
		result, err = s.diffContainerImages(ctx, args)
	} else {
		result, err = s.diffGitRefs(ctx, args)
	}

	if err != nil {
		logs.Warn(ctx, "Diff refs failed", "base_ref", args.GetBaseRef(), "target_ref", args.GetTargetRef(), "error", err)
		return nil, err
	}

	span.SetAttributes(
		otel.AttrMCPChangeCount.Int(len(result.GetChanges())),
		attribute.Bool("deputy.mcp.is_container_diff", isContainerDiff),
	)
	logs.Debug(ctx, "MCP tool completed", "tool", "diff_refs", "base_ref", args.GetBaseRef(), "target_ref", args.GetTargetRef(), "changes", len(result.GetChanges()), "is_container", isContainerDiff)

	return result, nil
}

// diffContainerImages compares two container images.
func (s *Server) diffContainerImages(ctx context.Context, args *mcpv1.DiffRefsRequest) (*mcpv1.DiffRefsResult, error) {
	baseRef := strings.TrimSpace(args.GetBaseRef())
	targetRef := strings.TrimSpace(args.GetTargetRef())
	platform := strings.TrimSpace(args.GetPlatform())

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
		return nil, fmt.Errorf("failed to scan base image %s: %w", baseRef, err)
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
		return nil, fmt.Errorf("failed to scan target image %s: %w", targetRef, err)
	}

	baseScan := baseResp.Msg
	targetScan := targetResp.Msg

	result := &mcpv1.DiffRefsResult{
		BaseRef:         baseRef,
		TargetRef:       targetRef,
		Platform:        platform,
		IsContainerDiff: proto.Bool(true),
	}

	// Build package maps for comparison
	basePackages := make(map[string]*packageInfo)
	for _, pkg := range baseScan.Packages {
		key := diffPackageKey(pkg.Purl, pkg.Ecosystem, pkg.Name)
		basePackages[key] = &packageInfo{Name: pkg.Name, Version: pkg.Version, Ecosystem: mcpOutputEcosystem(pkg.Ecosystem), PURL: pkg.Purl, Direct: pkg.Direct}
	}

	targetPackages := make(map[string]*packageInfo)
	for _, pkg := range targetScan.Packages {
		key := diffPackageKey(pkg.Purl, pkg.Ecosystem, pkg.Name)
		targetPackages[key] = &packageInfo{Name: pkg.Name, Version: pkg.Version, Ecosystem: mcpOutputEcosystem(pkg.Ecosystem), PURL: pkg.Purl, Direct: pkg.Direct}
	}

	// Find added and updated packages
	for key, targetPkg := range targetPackages {
		basePkg, exists := basePackages[key]
		if !exists {
			result.Changes = append(result.Changes, &mcpv1.DependencyChange{
				Name:          targetPkg.Name,
				TargetVersion: targetPkg.Version,
				Purl:          targetPkg.PURL,
				ChangeType:    "added",
				Direct:        proto.Bool(targetPkg.Direct),
				Ecosystem:     targetPkg.Ecosystem,
			})
			result.AddedCount++
		} else if basePkg.Version != targetPkg.Version {
			// Equal comparisons with different strings (1.2.3 vs v1.2.3) are
			// updated: the version did not move, only its spelling.
			changeType := "updated"
			switch cmp := compareVersions(basePkg.Version, targetPkg.Version); {
			case cmp < 0:
				changeType = "upgraded"
			case cmp > 0:
				changeType = "downgraded"
			}
			result.Changes = append(result.Changes, &mcpv1.DependencyChange{
				Name:          targetPkg.Name,
				BaseVersion:   basePkg.Version,
				TargetVersion: targetPkg.Version,
				Purl:          targetPkg.PURL,
				ChangeType:    changeType,
				Direct:        proto.Bool(targetPkg.Direct),
				Ecosystem:     targetPkg.Ecosystem,
			})
			result.UpdatedCount++
		}
	}

	// Find removed packages
	for key, basePkg := range basePackages {
		if _, exists := targetPackages[key]; !exists {
			result.Changes = append(result.Changes, &mcpv1.DependencyChange{
				Name:        basePkg.Name,
				BaseVersion: basePkg.Version,
				Purl:        basePkg.PURL,
				ChangeType:  "removed",
				Direct:      proto.Bool(basePkg.Direct),
				Ecosystem:   basePkg.Ecosystem,
			})
			result.RemovedCount++
		}
	}

	result.VulnerabilitiesBySeverity, result.Vulnerabilities = diffTargetVulnerabilities(targetScan)
	sortDependencyChanges(result.Changes)
	baseInternal := internalproto.ScanningResultFromProto(baseScan)
	targetInternal := internalproto.ScanningResultFromProto(targetScan)
	if baseInternal != nil && targetInternal != nil {
		containerDiff := internalproto.BuildContainerDiffResponseFromScanning(baseInternal, targetInternal)
		result.VulnerabilityChanges = containerVulnerabilityChangesProto(containerDiff.GetVulnerabilityChanges())
		result.ContainerSummary = containerSummaryProto(containerDiff.GetSummary())
	}

	return result, nil
}

// diffGitRefs compares dependencies between Git references.
func (s *Server) diffGitRefs(ctx context.Context, args *mcpv1.DiffRefsRequest) (*mcpv1.DiffRefsResult, error) {
	if args.GetPath() == "" {
		return nil, fmt.Errorf("path is required for Git ref comparison")
	}
	targetPath, err := normalizeLocalPath(args.GetPath())
	if err != nil {
		return nil, err
	}
	baseRef := strings.TrimSpace(args.GetBaseRef())
	targetRef := strings.TrimSpace(args.GetTargetRef())

	// Scan base ref
	baseReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: targetPath,
		Options: &scanv1.ScanOptions{
			Ecosystems:   normalizeMCPEcosystems(args.GetEcosystems()),
			ExcludePaths: s.excludePaths(args.GetExcludePaths()),
			Ref:          baseRef,
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_GIT,
			},
		},
	})
	baseResp, err := s.clients.Vulns.Scan(ctx, baseReq)
	if err != nil {
		return nil, fmt.Errorf("failed to scan base ref %s: %w", baseRef, err)
	}

	// Scan target ref
	targetReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: targetPath,
		Options: &scanv1.ScanOptions{
			Ecosystems:   normalizeMCPEcosystems(args.GetEcosystems()),
			ExcludePaths: s.excludePaths(args.GetExcludePaths()),
			Ref:          targetRef,
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_GIT,
			},
		},
	})
	targetResp, err := s.clients.Vulns.Scan(ctx, targetReq)
	if err != nil {
		return nil, fmt.Errorf("failed to scan target ref %s: %w", targetRef, err)
	}

	baseScan := baseResp.Msg
	targetScan := targetResp.Msg

	result := &mcpv1.DiffRefsResult{
		Path:            targetPath,
		BaseRef:         baseRef,
		TargetRef:       targetRef,
		BaseCommit:      strings.TrimSpace(baseScan.GetTarget().GetCommitHash()),
		TargetCommit:    strings.TrimSpace(targetScan.GetTarget().GetCommitHash()),
		IsContainerDiff: proto.Bool(false),
	}

	// Build package maps for comparison
	basePackages := make(map[string]*packageInfo)
	for _, pkg := range baseScan.Packages {
		key := diffPackageKey(pkg.Purl, pkg.Ecosystem, pkg.Name)
		basePackages[key] = &packageInfo{Name: pkg.Name, Version: pkg.Version, Ecosystem: mcpOutputEcosystem(pkg.Ecosystem), PURL: pkg.Purl, Direct: pkg.Direct}
	}

	targetPackages := make(map[string]*packageInfo)
	for _, pkg := range targetScan.Packages {
		key := diffPackageKey(pkg.Purl, pkg.Ecosystem, pkg.Name)
		targetPackages[key] = &packageInfo{Name: pkg.Name, Version: pkg.Version, Ecosystem: mcpOutputEcosystem(pkg.Ecosystem), PURL: pkg.Purl, Direct: pkg.Direct}
	}

	// Find added and updated packages
	for key, targetPkg := range targetPackages {
		basePkg, exists := basePackages[key]
		if !exists {
			result.Changes = append(result.Changes, &mcpv1.DependencyChange{
				Name:          targetPkg.Name,
				TargetVersion: targetPkg.Version,
				Purl:          targetPkg.PURL,
				ChangeType:    "added",
				Direct:        proto.Bool(targetPkg.Direct),
				Ecosystem:     targetPkg.Ecosystem,
			})
			result.AddedCount++
		} else if basePkg.Version != targetPkg.Version {
			// Equal comparisons with different strings (1.2.3 vs v1.2.3) are
			// updated: the version did not move, only its spelling.
			changeType := "updated"
			switch cmp := compareVersions(basePkg.Version, targetPkg.Version); {
			case cmp < 0:
				changeType = "upgraded"
			case cmp > 0:
				changeType = "downgraded"
			}
			result.Changes = append(result.Changes, &mcpv1.DependencyChange{
				Name:          targetPkg.Name,
				BaseVersion:   basePkg.Version,
				TargetVersion: targetPkg.Version,
				Purl:          targetPkg.PURL,
				ChangeType:    changeType,
				Direct:        proto.Bool(targetPkg.Direct),
				Ecosystem:     targetPkg.Ecosystem,
			})
			result.UpdatedCount++
		}
	}

	// Find removed packages
	for key, basePkg := range basePackages {
		if _, exists := targetPackages[key]; !exists {
			result.Changes = append(result.Changes, &mcpv1.DependencyChange{
				Name:        basePkg.Name,
				BaseVersion: basePkg.Version,
				Purl:        basePkg.PURL,
				ChangeType:  "removed",
				Direct:      proto.Bool(basePkg.Direct),
				Ecosystem:   basePkg.Ecosystem,
			})
			result.RemovedCount++
		}
	}

	result.VulnerabilitiesBySeverity, result.Vulnerabilities = diffTargetVulnerabilities(targetScan)
	sortDependencyChanges(result.Changes)

	return result, nil
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
func isContainerDiffInput(args *mcpv1.DiffRefsRequest) bool {
	if isGitRepoPath(args.GetPath()) {
		return looksLikeExplicitContainerImage(args.GetBaseRef()) && looksLikeExplicitContainerImage(args.GetTargetRef())
	}
	return isContainerImageRef(args.GetBaseRef()) && isContainerImageRef(args.GetTargetRef())
}

// isMixedContainerRefInput reports whether diff_refs was given one container
// image ref and one Git ref, an unsupported combination the caller rejects.
func isMixedContainerRefInput(args *mcpv1.DiffRefsRequest) bool {
	baseImage := isContainerImageRef(args.GetBaseRef())
	targetImage := isContainerImageRef(args.GetTargetRef())
	if baseImage == targetImage {
		return false
	}
	if strings.TrimSpace(args.GetPath()) == "" {
		return true
	}
	return isExplicitContainerSignal(args.GetBaseRef()) || isExplicitContainerSignal(args.GetTargetRef())
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

// packageInfo holds package identity for diff comparison.
type packageInfo struct {
	Name      string
	Version   string
	Ecosystem string
	PURL      string
	Direct    bool
}

// sortDependencyChanges orders diff changes deterministically: direct
// dependencies first, then by change kind, ecosystem, name, and version.
func sortDependencyChanges(changes []*mcpv1.DependencyChange) {
	slices.SortFunc(changes, compareDependencyChanges)
}

func compareDependencyChanges(a, b *mcpv1.DependencyChange) int {
	if a.GetDirect() != b.GetDirect() {
		if a.GetDirect() {
			return -1
		}
		return 1
	}
	if c := cmp.Compare(changeTypeRank(a.GetChangeType()), changeTypeRank(b.GetChangeType())); c != 0 {
		return c
	}
	if c := cmp.Compare(a.GetEcosystem(), b.GetEcosystem()); c != 0 {
		return c
	}
	if c := cmp.Compare(a.GetName(), b.GetName()); c != 0 {
		return c
	}
	if c := cmp.Compare(a.GetPurl(), b.GetPurl()); c != 0 {
		return c
	}
	if c := cmp.Compare(a.GetBaseVersion(), b.GetBaseVersion()); c != 0 {
		return c
	}
	return cmp.Compare(a.GetTargetVersion(), b.GetTargetVersion())
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

// diffTargetVulnerabilities summarizes the target ref's findings per severity
// level and projects each finding into its compact mcp.v1 explanation.
func diffTargetVulnerabilities(scanResult *scanv1.ScanResponse) (map[string]int32, []*mcpv1.VulnExplanation) {
	summary := map[string]int32{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"unknown":  0,
	}

	internalScanResult := internalproto.ScanningResultFromProto(scanResult)
	if internalScanResult == nil {
		return summary, nil
	}

	consolidated := vulnerability.ConsolidateAll(internalScanResult.Findings, internalScanResult.Advisories)
	summary["critical"] = consolidated.Stats.GetCritical()
	summary["high"] = consolidated.Stats.GetHigh()
	summary["medium"] = consolidated.Stats.GetMedium()
	summary["low"] = consolidated.Stats.GetLow()
	summary["unknown"] = consolidated.Stats.GetUnknown()

	vulns := make([]*mcpv1.VulnExplanation, 0, len(consolidated.Vulnerabilities))
	for _, vuln := range consolidated.Vulnerabilities {
		vulns = append(vulns, vulnExplanationProto(vuln, vulnExplanationOptions{referenceLimit: compactVulnReferenceLimit}))
	}

	return summary, vulns
}

// containerVulnerabilityChangesProto converts container diff vulnerability
// deltas to the mcp.v1 shape.
func containerVulnerabilityChangesProto(changes []*diffv1.ContainerVulnerabilityChange) []*mcpv1.DiffVulnChange {
	if len(changes) == 0 {
		return nil
	}
	out := make([]*mcpv1.DiffVulnChange, 0, len(changes))
	for _, change := range changes {
		if change == nil {
			continue
		}
		out = append(out, &mcpv1.DiffVulnChange{
			Id:            change.GetId(),
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

// containerSummaryProto converts container diff totals to the mcp.v1 shape.
func containerSummaryProto(summary *diffv1.ContainerDiffSummary) *mcpv1.ContainerSummary {
	if summary == nil {
		return nil
	}
	return &mcpv1.ContainerSummary{
		PackagesAdded:          summary.GetPackagesAdded(),
		PackagesRemoved:        summary.GetPackagesRemoved(),
		PackagesUpgraded:       summary.GetPackagesUpgraded(),
		PackagesDowngraded:     summary.GetPackagesDowngraded(),
		VulnerabilitiesAdded:   summary.GetVulnerabilitiesAdded(),
		VulnerabilitiesRemoved: summary.GetVulnerabilitiesRemoved(),
		VulnerabilitiesFixed:   summary.GetVulnerabilitiesFixed(),
		LayersAdded:            summary.GetLayersAdded(),
		LayersRemoved:          summary.GetLayersRemoved(),
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
		// Unspecified kinds stay absent on the wire per the package rule.
		return ""
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

// Truncation limits keep tool results compact for agent context windows;
// results carry counts and *Truncated flags so sampling is always detectable.
const (
	compactVulnReferenceLimit  = 5
	allVulnReferences          = -1
	maxMCPVulnerablePaths      = 50
	maxMCPPathsToTarget        = 20
	maxMCPGraphWhyPaths        = 10
	maxMCPGraphWhyShowAllPaths = 100
)

type vulnExplanationOptions struct {
	includeDetails bool
	referenceLimit int
}

// mcpFindingKind renders a FindingKind for agent output. The default
// (unspecified) is treated as a vulnerability and rendered as empty so results
// stay compact for the common case.
func mcpFindingKind(k vulnerabilityv1.FindingKind) string {
	switch k {
	case vulnerabilityv1.FindingKind_FINDING_KIND_MALWARE:
		return "malware"
	case vulnerabilityv1.FindingKind_FINDING_KIND_VULNERABILITY:
		return "vulnerability"
	default:
		return ""
	}
}

// mcpArtifactKind renders an ArtifactKind as a stable lowercase token.
func mcpArtifactKind(a vulnerabilityv1.ArtifactKind) string {
	switch a {
	case vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_PACKAGE:
		return "package"
	case vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_OS_PACKAGE:
		return "os_package"
	case vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_CONTAINER_IMAGE_REF:
		return "container_image_ref"
	case vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_GITHUB_ACTION:
		return "github_action"
	default:
		// Unspecified kinds stay absent on the wire per the package rule.
		return ""
	}
}

func referencesForMCP(values []string, limit int) ([]string, bool) {
	refs := stringsForMCP(values)
	if limit < 0 || len(refs) <= limit {
		return refs, false
	}
	return refs[:limit], true
}

func stringsForMCP(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return slices.Clone(values)
}

// referenceLimitForMCP resolves the optional referenceLimit input: absent
// means all references, mirroring the field's documented semantics.
func referenceLimitForMCP(limit *int32) int {
	if limit == nil {
		return allVulnReferences
	}
	return int(*limit)
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

// graphPathProto converts a graph path to its mcp.v1 shape: display names,
// structured node details, and the edge count as depth (a single-node path
// has depth 0).
func graphPathProto(path graph.Path) *mcpv1.GraphPath {
	return &mcpv1.GraphPath{
		Nodes:       pathToStrings(path),
		NodeDetails: pathToNodeDetails(path),
		Depth:       proto.Int32(int32(path.Len())),
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

func pathToNodeDetails(path graph.Path) []*mcpv1.GraphPathNode {
	result := make([]*mcpv1.GraphPathNode, len(path))
	for i, node := range path {
		result[i] = graphNodeProto(node)
	}
	return result
}

// graphNodeProto converts a graph node to its mcp.v1 shape with the canonical
// output ecosystem name.
func graphNodeProto(node *graph.Node) *mcpv1.GraphPathNode {
	if node == nil {
		return &mcpv1.GraphPathNode{}
	}
	return &mcpv1.GraphPathNode{
		Name:         node.GetName(),
		Version:      node.GetVersion(),
		Ecosystem:    mcpOutputEcosystem(node.GetEcosystem()),
		Purl:         node.GetPurl(),
		Direct:       proto.Bool(node.GetDirect()),
		Depth:        proto.Int32(node.GetDepth()),
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
