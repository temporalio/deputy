package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/analysis/osv"
	"github.com/picatz/deputy/internal/dependency/graph"
	"github.com/picatz/deputy/internal/logs"
	"github.com/picatz/deputy/internal/otel"
	internalproto "github.com/picatz/deputy/internal/proto"
	"github.com/picatz/deputy/internal/remediation"
	sbomx "github.com/picatz/deputy/internal/sbom"
	"github.com/picatz/deputy/internal/services"
	"github.com/picatz/deputy/internal/version"
	"github.com/picatz/deputy/internal/vulnerability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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
	server       *mcp.Server
	osv          osv.Client
	clients      *services.Clients
	toolNames    []string     // registered tool names for /info endpoint
	toolTimeouts ToolTimeouts // configurable timeouts for tool operations
}

// ServerOption configures a Server.
type ServerOption func(*Server)

// WithOSVClient configures a custom OSV client for the server.
func WithOSVClient(client osv.Client) ServerOption {
	return func(s *Server) {
		s.osv = client
	}
}

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

// NewServer creates a new Deputy MCP server with vulnerability analysis tools.
func NewServer(opts ...ServerOption) *Server {
	impl := &mcp.Implementation{
		Name:    "deputy",
		Version: version.Value,
	}

	server := mcp.NewServer(impl, nil)
	s := &Server{
		server:       server,
		osv:          osv.NewClient(),
		toolTimeouts: DefaultToolTimeouts(),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Create default clients if not provided
	if s.clients == nil {
		svc, err := services.New()
		if err != nil {
			// Fall back to nil clients - will fail on first use with clear error
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
	json.NewEncoder(w).Encode(map[string]any{
		"name":        "deputy",
		"version":     version.Value,
		"protocol":    "mcp",
		"transport":   "sse",
		"description": "Deputy MCP server for software supply chain security",
		"tools":       s.toolNames,
	})
}

// addTool is a helper that registers a tool and tracks its name for /info endpoint.
func addTool[T, R any](s *Server, tool *mcp.Tool, handler func(context.Context, *mcp.CallToolRequest, T) (*mcp.CallToolResult, R, error)) {
	mcp.AddTool(s.server, tool, handler)
	s.toolNames = append(s.toolNames, tool.Name)
}

// registerTools adds all Deputy tools to the MCP server.
func (s *Server) registerTools() {
	// Vulnerability explanation tools
	addTool(s, &mcp.Tool{
		Name:        "explain_vulnerability",
		Description: "Get detailed information about a vulnerability by its ID (CVE, GHSA, etc.)",
	}, s.explainVulnerability)

	addTool(s, &mcp.Tool{
		Name:        "explain_vulnerabilities",
		Description: "Get detailed information about multiple vulnerabilities by their IDs",
	}, s.explainVulnerabilities)

	// Package scanning tools
	addTool(s, &mcp.Tool{
		Name:        "scan_package",
		Description: "Check a single package for known vulnerabilities by name, version, and ecosystem",
	}, s.scanPackage)

	addTool(s, &mcp.Tool{
		Name:        "scan_directory",
		Description: "Scan a local directory for vulnerabilities by analyzing dependency manifests (go.mod, package.json, etc.)",
	}, s.scanDirectory)

	// Dependency tools
	addTool(s, &mcp.Tool{
		Name:        "list_dependencies",
		Description: "List all dependencies in a directory, optionally filtering to direct dependencies only",
	}, s.listDependencies)

	// SBOM tools
	addTool(s, &mcp.Tool{
		Name:        "generate_sbom",
		Description: "Generate a Software Bill of Materials (SBOM) for a directory or repository",
	}, s.generateSBOM)

	// Remediation tools
	addTool(s, &mcp.Tool{
		Name:        "get_remediation",
		Description: "Get remediation commands for fixing vulnerabilities in a scanned directory",
	}, s.getRemediation)

	// Graph analysis tools
	addTool(s, &mcp.Tool{
		Name:        "analyze_dependency_graph",
		Description: "Analyze the dependency graph to find paths to vulnerable packages",
	}, s.analyzeDependencyGraph)

	addTool(s, &mcp.Tool{
		Name:        "graph_why",
		Description: "Show why a package is in the dependency graph - traces dependency paths from direct dependencies to target package (like 'go mod why' for all ecosystems)",
	}, s.graphWhy)

	addTool(s, &mcp.Tool{
		Name:        "graph_needs",
		Description: "Show what packages depend on a given package - reverse lookup to understand impact of upgrading or removing a dependency",
	}, s.graphNeeds)

	// Triage tools
	addTool(s, &mcp.Tool{
		Name:        "triage_vulnerabilities",
		Description: "Prioritize and summarize vulnerabilities by severity, exploitability, and fixability to help focus remediation efforts",
	}, s.triageVulnerabilities)

	// Container scanning tools
	addTool(s, &mcp.Tool{
		Name:        "scan_container",
		Description: "Scan a container image for vulnerabilities. Supports remote registries (nginx:1.25, ghcr.io/owner/app:v1) and local Docker daemon images (docker-daemon://myapp:latest).",
	}, s.scanContainer)

	// Diff tools
	addTool(s, &mcp.Tool{
		Name:        "diff_refs",
		Description: "Compare dependencies between Git references (branches, tags, commits) or container images. Shows added, removed, and updated packages with vulnerability analysis.",
	}, s.diffRefs)
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

// === Input/Output Types ===

// ExplainVulnInput is the input for the explain_vulnerability tool.
type ExplainVulnInput struct {
	ID string `json:"id" jsonschema:"Vulnerability ID (e.g., CVE-2021-44228, GHSA-xxxx-xxxx-xxxx)"`
}

// VulnExplanation is the output for vulnerability explanation.
type VulnExplanation struct {
	ID            string   `json:"id"`
	Aliases       []string `json:"aliases,omitempty"`
	Summary       string   `json:"summary"`
	Details       string   `json:"details,omitempty"`
	Severity      string   `json:"severity"`
	FixedVersions []string `json:"fixed_versions,omitempty"`
	References    []string `json:"references,omitempty"`
	Published     string   `json:"published,omitempty"`
	Modified      string   `json:"modified,omitempty"`
}

// ExplainVulnsInput is the input for the explain_vulnerabilities tool.
type ExplainVulnsInput struct {
	IDs []string `json:"ids" jsonschema:"List of vulnerability IDs to explain"`
}

// VulnsExplanation is the output for batch vulnerability explanation.
type VulnsExplanation struct {
	Vulnerabilities []VulnExplanation `json:"vulnerabilities"`
	Errors          []string          `json:"errors,omitempty"`
}

// ScanPackageInput is the input for the scan_package tool.
type ScanPackageInput struct {
	Name      string `json:"name" jsonschema:"Package name (e.g., lodash, github.com/foo/bar)"`
	Version   string `json:"version" jsonschema:"Package version"`
	Ecosystem string `json:"ecosystem" jsonschema:"Package ecosystem (e.g., npm, Go, PyPI, Maven, Cargo)"`
}

// ScanResult is the output for package scanning.
type ScanResult struct {
	Package         string            `json:"package"`
	Version         string            `json:"version"`
	Ecosystem       string            `json:"ecosystem"`
	Vulnerabilities []VulnExplanation `json:"vulnerabilities"`
	Clean           bool              `json:"clean"`
}

// ScanDirectoryInput is the input for the scan_directory tool.
type ScanDirectoryInput struct {
	Path       string   `json:"path" jsonschema:"Path to the directory to scan"`
	Ecosystems []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to scan (e.g., go, npm). Scans all if empty."`
}

// DirectoryScanResult is the output for directory scanning.
type DirectoryScanResult struct {
	Path              string            `json:"path"`
	PackagesScanned   int               `json:"packages_scanned"`
	VulnerabilitiesBy map[string]int    `json:"vulnerabilities_by_severity"`
	Vulnerabilities   []VulnExplanation `json:"vulnerabilities"`
	Clean             bool              `json:"clean"`
	ScanTime          string            `json:"scan_time"`
}

// ListDependenciesInput is the input for the list_dependencies tool.
type ListDependenciesInput struct {
	Path       string   `json:"path" jsonschema:"Path to the directory to analyze"`
	DirectOnly bool     `json:"direct_only,omitempty" jsonschema:"If true, only list direct dependencies"`
	Ecosystems []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
}

// DependencyInfo represents a single dependency.
type DependencyInfo struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	PURL      string   `json:"purl,omitempty"`
	Direct    bool     `json:"direct"`
	Locations []string `json:"locations,omitempty"`
}

// ListDependenciesResult is the output for the list_dependencies tool.
type ListDependenciesResult struct {
	Path         string           `json:"path"`
	Total        int              `json:"total"`
	Direct       int              `json:"direct"`
	Transitive   int              `json:"transitive"`
	Dependencies []DependencyInfo `json:"dependencies"`
}

// GenerateSBOMInput is the input for the generate_sbom tool.
type GenerateSBOMInput struct {
	Path           string   `json:"path" jsonschema:"Path to the directory or repository"`
	Ref            string   `json:"ref,omitempty" jsonschema:"Git reference (branch, tag, commit). Defaults to HEAD."`
	Format         string   `json:"format,omitempty" jsonschema:"Output format: cyclonedx-json, spdx-json, or protobom-json. Defaults to cyclonedx-json."`
	EnrichLicenses bool     `json:"enrich_licenses,omitempty" jsonschema:"Enrich SBOM with license information from deps.dev"`
	Ecosystems     []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
}

// SBOMResult is the output for the generate_sbom tool.
type SBOMResult struct {
	Path       string `json:"path"`
	Ref        string `json:"ref"`
	Commit     string `json:"commit,omitempty"`
	Format     string `json:"format"`
	Components int    `json:"components"`
	SBOM       string `json:"sbom"`
}

// GetRemediationInput is the input for the get_remediation tool.
type GetRemediationInput struct {
	Path       string   `json:"path" jsonschema:"Path to the directory to analyze for remediation"`
	Ecosystems []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
}

// RemediationCommand represents a remediation action.
type RemediationCommand struct {
	Manager    string   `json:"manager"`
	Command    string   `json:"command"`
	Path       string   `json:"path,omitempty"`
	Hint       string   `json:"hint,omitempty"`
	IsDirect   bool     `json:"is_direct"`
	Executable bool     `json:"executable"`
	Groups     []string `json:"groups,omitempty"`
}

// GetRemediationResult is the output for the get_remediation tool.
type GetRemediationResult struct {
	Path                  string               `json:"path"`
	VulnerabilitiesFound  int                  `json:"vulnerabilities_found"`
	RemediableCount       int                  `json:"remediable_count"`
	UnfixableCount        int                  `json:"unfixable_count"`
	Commands              []RemediationCommand `json:"commands"`
	StdlibUpgrade         string               `json:"stdlib_upgrade,omitempty"`
	UnfixableVulns        []string             `json:"unfixable_vulns,omitempty"`
}

// AnalyzeGraphInput is the input for the analyze_dependency_graph tool.
type AnalyzeGraphInput struct {
	Path       string   `json:"path" jsonschema:"Path to the directory to analyze"`
	TargetPURL string   `json:"target_purl,omitempty" jsonschema:"Optional PURL to find paths to (e.g., pkg:npm/lodash@4.17.15)"`
	Ecosystems []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
}

// GraphPath represents a dependency path.
type GraphPath struct {
	Nodes []string `json:"nodes"`
	Depth int      `json:"depth"`
}

// GraphStats contains statistics about the dependency graph.
type GraphStats struct {
	TotalNodes      int            `json:"total_nodes"`
	DirectNodes     int            `json:"direct_nodes"`
	TransitiveNodes int            `json:"transitive_nodes"`
	MaxDepth        int            `json:"max_depth"`
	VulnerableNodes int            `json:"vulnerable_nodes"`
	Ecosystems      map[string]int `json:"ecosystems"`
}

// AnalyzeGraphResult is the output for the analyze_dependency_graph tool.
type AnalyzeGraphResult struct {
	Path            string      `json:"path"`
	Stats           GraphStats  `json:"stats"`
	VulnerablePaths []GraphPath `json:"vulnerable_paths,omitempty"`
	PathsToTarget   []GraphPath `json:"paths_to_target,omitempty"`
}

// GraphWhyInput is the input for the graph_why tool.
type GraphWhyInput struct {
	Path       string   `json:"path" jsonschema:"Path to the directory to analyze"`
	Package    string   `json:"package" jsonschema:"Package name to trace (e.g., lodash, golang.org/x/crypto)"`
	ShowAll    bool     `json:"show_all,omitempty" jsonschema:"Show all dependency paths, not just the shortest"`
	Ecosystems []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
}

// GraphWhyResult is the output for the graph_why tool.
type GraphWhyResult struct {
	Package    string      `json:"package"`
	Version    string      `json:"version,omitempty"`
	PURL       string      `json:"purl,omitempty"`
	Direct     bool        `json:"direct"`
	Found      bool        `json:"found"`
	Paths      []GraphPath `json:"paths,omitempty"`
	PathCount  int         `json:"path_count"`
	Message    string      `json:"message,omitempty"`
}

// GraphNeedsInput is the input for the graph_needs tool.
type GraphNeedsInput struct {
	Path       string   `json:"path" jsonschema:"Path to the directory to analyze"`
	Package    string   `json:"package" jsonschema:"Package name to find dependents of"`
	Ecosystems []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
}

// GraphNeedsResult is the output for the graph_needs tool.
type GraphNeedsResult struct {
	Package        string           `json:"package"`
	Version        string           `json:"version,omitempty"`
	PURL           string           `json:"purl,omitempty"`
	Found          bool             `json:"found"`
	Dependents     []DependencyInfo `json:"dependents"`
	DirectCount    int              `json:"direct_count"`
	TransitiveCount int             `json:"transitive_count"`
}

// TriageInput is the input for the triage_vulnerabilities tool.
type TriageInput struct {
	Path       string   `json:"path" jsonschema:"Path to the directory to analyze"`
	Ecosystems []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include"`
}

// TriagedVuln represents a prioritized vulnerability.
type TriagedVuln struct {
	ID            string   `json:"id"`
	Severity      string   `json:"severity"`
	Package       string   `json:"package"`
	Version       string   `json:"version"`
	IsDirect      bool     `json:"is_direct"`
	HasFix        bool     `json:"has_fix"`
	FixedVersions []string `json:"fixed_versions,omitempty"`
	Summary       string   `json:"summary"`
	Priority      string   `json:"priority"` // "critical", "high", "medium", "low"
	PriorityReason string  `json:"priority_reason"`
}

// TriageResult is the output for the triage_vulnerabilities tool.
type TriageResult struct {
	Path             string        `json:"path"`
	TotalVulns       int           `json:"total_vulns"`
	CriticalCount    int           `json:"critical_count"`
	HighCount        int           `json:"high_count"`
	MediumCount      int           `json:"medium_count"`
	LowCount         int           `json:"low_count"`
	FixableCount     int           `json:"fixable_count"`
	UnfixableCount   int           `json:"unfixable_count"`
	DirectVulns      int           `json:"direct_vulns"`
	TransitiveVulns  int           `json:"transitive_vulns"`
	Vulnerabilities  []TriagedVuln `json:"vulnerabilities"`
	Recommendations  []string      `json:"recommendations"`
}

// ScanContainerInput is the input for the scan_container tool.
type ScanContainerInput struct {
	Image    string `json:"image" jsonschema:"Container image reference (e.g., nginx:1.25, ghcr.io/owner/app:v1.0.0, docker-daemon://myapp:latest)"`
	Platform string `json:"platform,omitempty" jsonschema:"Target platform (e.g., linux/amd64, linux/arm64). Defaults to current platform."`
}

// ContainerScanResult is the output for container scanning.
type ContainerScanResult struct {
	Image             string            `json:"image"`
	Platform          string            `json:"platform,omitempty"`
	PackagesScanned   int               `json:"packages_scanned"`
	VulnerabilitiesBy map[string]int    `json:"vulnerabilities_by_severity"`
	Vulnerabilities   []VulnExplanation `json:"vulnerabilities"`
	Clean             bool              `json:"clean"`
	ScanTime          string            `json:"scan_time"`
}

// DiffRefsInput is the input for the diff_refs tool.
type DiffRefsInput struct {
	Path       string   `json:"path" jsonschema:"Path to the repository (for Git refs) or base image reference (for container diff)"`
	BaseRef    string   `json:"base_ref" jsonschema:"Base Git reference (branch, tag, commit) or container image reference"`
	TargetRef  string   `json:"target_ref" jsonschema:"Target Git reference or container image reference to compare against"`
	Ecosystems []string `json:"ecosystems,omitempty" jsonschema:"Optional list of ecosystems to include (for Git diffs)"`
}

// DependencyChange represents a change to a dependency.
type DependencyChange struct {
	Name          string `json:"name"`
	BaseVersion   string `json:"base_version,omitempty"`
	TargetVersion string `json:"target_version,omitempty"`
	ChangeType    string `json:"change_type"` // "added", "removed", "upgraded", "downgraded", "updated"
	IsDirect      bool   `json:"is_direct"`
	Ecosystem     string `json:"ecosystem"`
}

// DiffRefsResult is the output for the diff_refs tool.
type DiffRefsResult struct {
	Path            string             `json:"path"`
	BaseRef         string             `json:"base_ref"`
	TargetRef       string             `json:"target_ref"`
	IsContainerDiff bool               `json:"is_container_diff"`
	Changes         []DependencyChange `json:"changes"`
	AddedCount      int                `json:"added_count"`
	RemovedCount    int                `json:"removed_count"`
	UpdatedCount    int                `json:"updated_count"`
	Vulnerabilities []VulnExplanation  `json:"vulnerabilities,omitempty"`
	VulnSummary     map[string]int     `json:"vuln_summary,omitempty"`
}

// === Tool Implementations ===

func (s *Server) explainVulnerability(ctx context.Context, req *mcp.CallToolRequest, args ExplainVulnInput) (*mcp.CallToolResult, VulnExplanation, error) {
	startTime := time.Now()

	// Apply timeout for quick operations
	ctx, cancel := s.withTimeout(ctx, s.toolTimeouts.Default)
	defer cancel()

	ctx, span := otel.StartSpan(ctx, "deputy.mcp.explain_vulnerability",
		trace.WithAttributes(otel.AttrMCPTool.String("explain_vulnerability")))
	defer span.End()

	logs.Debug(ctx, "MCP tool invoked", "tool", "explain_vulnerability", "vuln_id", args.ID)

	if args.ID == "" {
		err := fmt.Errorf("vulnerability ID is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "explain_vulnerability", time.Since(startTime).Seconds(), false)
		return nil, VulnExplanation{}, err
	}

	span.SetAttributes(otel.AttrMCPVulnID.String(args.ID))

	vuln, err := s.osv.GetVulnByID(ctx, args.ID)
	if err != nil {
		err = fmt.Errorf("failed to fetch vulnerability %s: %w", args.ID, err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "explain_vulnerability", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Failed to fetch vulnerability", "vuln_id", args.ID, "error", err)
		return nil, VulnExplanation{}, err
	}
	if vuln == nil {
		err = fmt.Errorf("vulnerability %s not found", args.ID)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "explain_vulnerability", time.Since(startTime).Seconds(), false)
		return nil, VulnExplanation{}, err
	}

	severity := extractSeverity(vuln)

	var refs []string
	for _, ref := range vuln.References {
		refs = append(refs, ref.URL)
	}

	explanation := VulnExplanation{
		ID:         vuln.ID,
		Aliases:    vuln.Aliases,
		Summary:    vuln.Summary,
		Details:    vuln.Details,
		Severity:   severity.Level.String(),
		References: refs,
	}

	if !vuln.Published.IsZero() {
		explanation.Published = vuln.Published.Format("2006-01-02")
	}
	if !vuln.Modified.IsZero() {
		explanation.Modified = vuln.Modified.Format("2006-01-02")
	}

	fixedSet := make(map[string]struct{})
	for _, affected := range vuln.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					fixedSet[event.Fixed] = struct{}{}
				}
			}
		}
	}
	for v := range fixedSet {
		explanation.FixedVersions = append(explanation.FixedVersions, v)
	}

	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "explain_vulnerability", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "explain_vulnerability", "vuln_id", args.ID)

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

	if len(args.IDs) == 0 {
		err := fmt.Errorf("at least one vulnerability ID is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "explain_vulnerabilities", time.Since(startTime).Seconds(), false)
		return nil, VulnsExplanation{}, err
	}

	span.SetAttributes(otel.AttrMCPVulnCount.Int(len(args.IDs)))

	result := VulnsExplanation{
		Vulnerabilities: make([]VulnExplanation, 0, len(args.IDs)),
	}

	for _, id := range args.IDs {
		_, explanation, err := s.explainVulnerability(ctx, req, ExplainVulnInput{ID: id})
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", id, err))
			continue
		}
		result.Vulnerabilities = append(result.Vulnerabilities, explanation)
	}

	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "explain_vulnerabilities", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "explain_vulnerabilities", "found", len(result.Vulnerabilities), "errors", len(result.Errors))

	return nil, result, nil
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

	if args.Name == "" {
		err := fmt.Errorf("package name is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "scan_package", time.Since(startTime).Seconds(), false)
		return nil, ScanResult{}, err
	}
	if args.Version == "" {
		err := fmt.Errorf("package version is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "scan_package", time.Since(startTime).Seconds(), false)
		return nil, ScanResult{}, err
	}
	if args.Ecosystem == "" {
		err := fmt.Errorf("package ecosystem is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "scan_package", time.Since(startTime).Seconds(), false)
		return nil, ScanResult{}, err
	}

	span.SetAttributes(
		attribute.String("deputy.mcp.package", args.Name),
		attribute.String("deputy.mcp.version", args.Version),
		attribute.String("deputy.mcp.ecosystem", args.Ecosystem),
	)

	pkgInput := osv.PkgInput{
		QueryKey: osv.QueryKey{
			Name:      args.Name,
			Version:   args.Version,
			Ecosystem: args.Ecosystem,
		},
	}

	findings, advisories, err := osv.Query(ctx, s.osv, []osv.PkgInput{pkgInput})
	if err != nil {
		err = fmt.Errorf("failed to scan package: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "scan_package", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Package scan failed", "package", args.Name, "error", err)
		return nil, ScanResult{}, err
	}

	result := ScanResult{
		Package:         args.Name,
		Version:         args.Version,
		Ecosystem:       args.Ecosystem,
		Vulnerabilities: make([]VulnExplanation, 0),
		Clean:           len(findings) == 0,
	}

	for _, finding := range findings {
		advisory, ok := advisories[finding.AdvisoryID]
		if !ok {
			continue
		}
		result.Vulnerabilities = append(result.Vulnerabilities, VulnExplanation{
			ID:            advisory.Id,
			Aliases:       advisory.Aliases,
			Summary:       advisory.Summary,
			Details:       advisory.Details,
			Severity:      advisory.Severity.Level.String(),
			FixedVersions: advisory.FixedVersions,
			References:    advisory.References,
		})
	}

	span.SetAttributes(otel.AttrMCPVulnCount.Int(len(result.Vulnerabilities)))
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "scan_package", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "scan_package", "package", args.Name, "vulns", len(result.Vulnerabilities), "clean", result.Clean)

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

	if args.Path == "" {
		err := fmt.Errorf("path is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "scan_directory", time.Since(startTime).Seconds(), false)
		return nil, DirectoryScanResult{}, err
	}

	span.SetAttributes(otel.AttrTargetPath.String(args.Path))

	// Build proto request
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: args.Path,
		Options: &scanv1.ScanOptions{
			Ecosystems: args.Ecosystems,
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
		logs.Warn(ctx, "Directory scan failed", "path", args.Path, "error", err)
		return nil, DirectoryScanResult{}, err
	}

	scanResult := resp.Msg
	result := DirectoryScanResult{
		Path:            args.Path,
		PackagesScanned: int(scanResult.PackagesScanned),
		VulnerabilitiesBy: map[string]int{
			"critical": int(scanResult.Stats.GetCritical()),
			"high":     int(scanResult.Stats.GetHigh()),
			"medium":   int(scanResult.Stats.GetMedium()),
			"low":      int(scanResult.Stats.GetLow()),
		},
		Vulnerabilities: make([]VulnExplanation, 0),
		Clean:           scanResult.Stats.GetUnique() == 0,
		ScanTime:        time.Since(startTime).String(),
	}

	// Convert findings to explanations
	seen := make(map[string]bool)
	for _, finding := range scanResult.Findings {
		if seen[finding.AdvisoryId] {
			continue
		}
		seen[finding.AdvisoryId] = true

		advisory, ok := scanResult.Advisories[finding.AdvisoryId]
		if !ok {
			continue
		}
		result.Vulnerabilities = append(result.Vulnerabilities, VulnExplanation{
			ID:            advisory.Id,
			Aliases:       advisory.Aliases,
			Summary:       advisory.Summary,
			Details:       advisory.Details,
			Severity:      advisory.Severity.GetLevel().String(),
			FixedVersions: advisory.FixedVersions,
			References:    advisory.References,
		})
	}

	span.SetAttributes(
		otel.AttrMCPPackageCount.Int(int(scanResult.PackagesScanned)),
		otel.AttrMCPVulnCount.Int(int(scanResult.Stats.GetUnique())),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "scan_directory", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "scan_directory", "path", args.Path, "packages", result.PackagesScanned, "vulns", scanResult.Stats.GetUnique(), "clean", result.Clean)

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

	if args.Path == "" {
		err := fmt.Errorf("path is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "list_dependencies", time.Since(startTime).Seconds(), false)
		return nil, ListDependenciesResult{}, err
	}

	span.SetAttributes(otel.AttrTargetPath.String(args.Path))

	// Build proto request for ListPackages
	listReq := connect.NewRequest(&listv1.ListPackagesRequest{
		Target: args.Path,
		Options: &listv1.ListOptions{
			Ecosystems: args.Ecosystems,
			OnlyDirect: args.DirectOnly,
		},
	})

	resp, err := s.clients.Inventory.ListPackages(ctx, listReq)
	if err != nil {
		err = fmt.Errorf("failed to analyze dependencies: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "list_dependencies", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "List dependencies failed", "path", args.Path, "error", err)
		return nil, ListDependenciesResult{}, err
	}

	listResult := resp.Msg
	result := ListDependenciesResult{
		Path:         args.Path,
		Dependencies: make([]DependencyInfo, 0, len(listResult.Packages)),
		Total:        int(listResult.Stats.GetTotalPackages()),
		Direct:       int(listResult.Stats.GetDirectPackages()),
		Transitive:   int(listResult.Stats.GetTransitivePackages()),
	}

	for _, pkg := range listResult.Packages {
		dep := DependencyInfo{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: pkg.Ecosystem,
			Direct:    pkg.Direct,
			Locations: pkg.Locations,
			PURL:      pkg.Purl,
		}
		result.Dependencies = append(result.Dependencies, dep)
	}

	span.SetAttributes(otel.AttrMCPPackageCount.Int(result.Total))
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "list_dependencies", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "list_dependencies", "path", args.Path, "total", result.Total, "direct", result.Direct, "transitive", result.Transitive)

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

	if args.Path == "" {
		err := fmt.Errorf("path is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "generate_sbom", time.Since(startTime).Seconds(), false)
		return nil, SBOMResult{}, err
	}

	format := args.Format
	if format == "" {
		format = "cyclonedx-json"
	}

	// Validate format
	switch format {
	case "cyclonedx-json", "spdx-json", "protobom-json":
		// Valid
	default:
		err := fmt.Errorf("unsupported format %q: must be cyclonedx-json, spdx-json, or protobom-json", format)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "generate_sbom", time.Since(startTime).Seconds(), false)
		return nil, SBOMResult{}, err
	}

	span.SetAttributes(
		otel.AttrTargetPath.String(args.Path),
		attribute.String("deputy.mcp.sbom_format", format),
	)

	opts := sbomx.Options{
		Ref:            args.Ref,
		Ecosystems:     args.Ecosystems,
		EnrichLicenses: args.EnrichLicenses,
		LicenseSource:  "depsdev",
	}

	sbomResult, err := sbomx.Generate(ctx, args.Path, opts)
	if err != nil {
		err = fmt.Errorf("failed to generate SBOM: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "generate_sbom", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "SBOM generation failed", "path", args.Path, "error", err)
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
	logs.Debug(ctx, "MCP tool completed", "tool", "generate_sbom", "path", args.Path, "format", format, "components", components)

	return nil, SBOMResult{
		Path:       args.Path,
		Ref:        sbomResult.Ref,
		Commit:     sbomResult.Commit,
		Format:     format,
		Components: components,
		SBOM:       sb.String(),
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

	if args.Path == "" {
		err := fmt.Errorf("path is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "get_remediation", time.Since(startTime).Seconds(), false)
		return nil, GetRemediationResult{}, err
	}

	span.SetAttributes(otel.AttrTargetPath.String(args.Path))

	// Build proto request
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: args.Path,
		Options: &scanv1.ScanOptions{
			Ecosystems: args.Ecosystems,
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
		logs.Warn(ctx, "Remediation scan failed", "path", args.Path, "error", err)
		return nil, GetRemediationResult{}, err
	}

	// Convert proto response to internal types for remediation analysis
	scanResult := internalproto.ScanningResultFromProto(resp.Msg)

	// Consolidate vulnerabilities for remediation analysis
	consolidated := vulnerability.ConsolidateAll(scanResult.Findings, scanResult.Advisories)

	// Get remediation commands
	commands, stdlibUpgrade := remediation.CommandsFromConsolidated(consolidated.Vulnerabilities)

	// Identify unfixable vulnerabilities
	var unfixable []string
	remediableCount := 0
	for _, v := range consolidated.Vulnerabilities {
		if len(v.FixedVersions) == 0 {
			unfixable = append(unfixable, v.PrimaryID)
		} else {
			remediableCount++
		}
	}

	result := GetRemediationResult{
		Path:                 args.Path,
		VulnerabilitiesFound: int(scanResult.Stats.Unique),
		RemediableCount:      remediableCount,
		UnfixableCount:       len(unfixable),
		Commands:             make([]RemediationCommand, 0, len(commands)),
		StdlibUpgrade:        stdlibUpgrade,
		UnfixableVulns:       unfixable,
	}

	for _, cmd := range commands {
		result.Commands = append(result.Commands, RemediationCommand{
			Manager:    cmd.Manager,
			Command:    cmd.Command,
			Path:       cmd.Path,
			Hint:       cmd.Hint,
			IsDirect:   cmd.IsDirect,
			Executable: cmd.Executable,
			Groups:     cmd.Groups,
		})
	}

	span.SetAttributes(
		otel.AttrMCPVulnCount.Int(result.VulnerabilitiesFound),
		attribute.Int("deputy.mcp.remediable_count", result.RemediableCount),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "get_remediation", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "get_remediation", "path", args.Path, "vulns", result.VulnerabilitiesFound, "remediable", result.RemediableCount, "unfixable", result.UnfixableCount)

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

	span.SetAttributes(otel.AttrTargetPath.String(args.Path))

	// Build proto request with graph enabled
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: args.Path,
		Options: &scanv1.ScanOptions{
			Ecosystems: args.Ecosystems,
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_DIR,
			},
			GraphOptions: &scanv1.GraphOptions{
				Enabled: true,
			},
		},
	})

	resp, err := s.clients.Vulns.Scan(ctx, scanReq)
	if err != nil {
		err = fmt.Errorf("scan failed: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "analyze_dependency_graph", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Graph analysis failed", "path", args.Path, "error", err)
		return nil, AnalyzeGraphResult{}, err
	}

	// Convert proto response to internal types for graph analysis
	scanResult := internalproto.ScanningResultFromProto(resp.Msg)

	result := AnalyzeGraphResult{
		Path: args.Path,
	}

	// If no graph was built, build one from inventory
	depGraph := scanResult.Graph
	if depGraph == nil {
		depGraph = graph.FromInventory(scanResult.Packages, scanResult.Direct)
		depGraph.AnnotateVulns(scanResult.Findings, scanResult.Advisories)
	}

	// Get stats
	stats := depGraph.Stats()
	result.Stats = GraphStats{
		TotalNodes:      stats.TotalNodes,
		DirectNodes:     stats.DirectNodes,
		TransitiveNodes: stats.TransitiveNodes,
		MaxDepth:        stats.MaxDepth,
		VulnerableNodes: stats.VulnerableNodes,
		Ecosystems:      stats.Ecosystems,
	}

	// Find vulnerable paths
	vulnPaths := depGraph.VulnerablePaths()
	for _, path := range vulnPaths {
		if len(result.VulnerablePaths) >= 50 {
			break // Limit to 50 paths
		}
		result.VulnerablePaths = append(result.VulnerablePaths, GraphPath{
			Nodes: pathToStrings(path),
			Depth: path.Len(),
		})
	}

	// If a target PURL is specified, find paths to it
	if args.TargetPURL != "" {
		paths := depGraph.PathsTo(args.TargetPURL)
		for _, path := range paths {
			if len(result.PathsToTarget) >= 20 {
				break // Limit to 20 paths
			}
			result.PathsToTarget = append(result.PathsToTarget, GraphPath{
				Nodes: pathToStrings(path),
				Depth: path.Len(),
			})
		}
	}

	span.SetAttributes(
		otel.AttrMCPPackageCount.Int(result.Stats.TotalNodes),
		attribute.Int("deputy.mcp.vulnerable_nodes", result.Stats.VulnerableNodes),
		otel.AttrMCPGraphPathCount.Int(len(result.VulnerablePaths)),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "analyze_dependency_graph", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "analyze_dependency_graph", "path", args.Path, "nodes", result.Stats.TotalNodes, "vulnerable_nodes", result.Stats.VulnerableNodes)

	return nil, result, nil
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

	if args.Path == "" {
		err := fmt.Errorf("path is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "graph_why", time.Since(startTime).Seconds(), false)
		return nil, GraphWhyResult{}, err
	}
	if args.Package == "" {
		err := fmt.Errorf("package name is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "graph_why", time.Since(startTime).Seconds(), false)
		return nil, GraphWhyResult{}, err
	}

	span.SetAttributes(
		otel.AttrTargetPath.String(args.Path),
		otel.AttrMCPGraphPackage.String(args.Package),
	)

	// Build proto request with graph enabled
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: args.Path,
		Options: &scanv1.ScanOptions{
			Ecosystems: args.Ecosystems,
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_DIR,
			},
			GraphOptions: &scanv1.GraphOptions{
				Enabled: true,
			},
		},
	})

	resp, err := s.clients.Vulns.Scan(ctx, scanReq)
	if err != nil {
		err = fmt.Errorf("scan failed: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "graph_why", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Graph why failed", "path", args.Path, "package", args.Package, "error", err)
		return nil, GraphWhyResult{}, err
	}

	// Convert proto response to internal types for graph analysis
	scanResult := internalproto.ScanningResultFromProto(resp.Msg)

	// Build graph from inventory if not already built
	depGraph := scanResult.Graph
	if depGraph == nil {
		depGraph = graph.FromInventory(scanResult.Packages, scanResult.Direct)
	}

	// Find matching nodes using ranked matching
	matches := findMatchingNodes(depGraph, args.Package)
	if len(matches) == 0 {
		span.SetAttributes(otel.AttrMCPGraphFound.Bool(false))
		otel.SetSpanOK(span)
		otel.RecordMCPToolCall(ctx, "graph_why", time.Since(startTime).Seconds(), true)
		logs.Debug(ctx, "MCP tool completed", "tool", "graph_why", "package", args.Package, "found", false)
		return nil, GraphWhyResult{
			Package: args.Package,
			Found:   false,
			Message: fmt.Sprintf("Package %q not found in dependency graph", args.Package),
		}, nil
	}

	// Use the best match
	match := matches[0]
	result := GraphWhyResult{
		Package: match.Name,
		Version: match.Version,
		PURL:    match.PURL,
		Direct:  match.Direct,
		Found:   true,
	}

	// If direct dependency, no paths needed
	if match.Direct {
		result.Message = "Direct dependency"
		span.SetAttributes(
			otel.AttrMCPGraphFound.Bool(true),
			otel.AttrMCPGraphDirect.Bool(true),
		)
		otel.SetSpanOK(span)
		otel.RecordMCPToolCall(ctx, "graph_why", time.Since(startTime).Seconds(), true)
		logs.Debug(ctx, "MCP tool completed", "tool", "graph_why", "package", args.Package, "found", true, "direct", true)
		return nil, result, nil
	}

	// Find paths to the package
	paths := depGraph.PathsTo(match.PURL)
	if len(paths) == 0 {
		result.Message = "No dependency path found (may be from compiled binary or lockfile)"
		span.SetAttributes(
			otel.AttrMCPGraphFound.Bool(true),
			otel.AttrMCPGraphPathCount.Int(0),
		)
		otel.SetSpanOK(span)
		otel.RecordMCPToolCall(ctx, "graph_why", time.Since(startTime).Seconds(), true)
		logs.Debug(ctx, "MCP tool completed", "tool", "graph_why", "package", args.Package, "found", true, "paths", 0)
		return nil, result, nil
	}

	// Convert paths
	limit := 10
	if args.ShowAll {
		limit = 100
	}
	for i, path := range paths {
		if i >= limit {
			break
		}
		result.Paths = append(result.Paths, GraphPath{
			Nodes: pathToStrings(path),
			Depth: path.Len(),
		})
	}
	result.PathCount = len(paths)

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
	logs.Debug(ctx, "MCP tool completed", "tool", "graph_why", "package", args.Package, "found", true, "paths", result.PathCount)

	return nil, result, nil
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

	if args.Path == "" {
		err := fmt.Errorf("path is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "graph_needs", time.Since(startTime).Seconds(), false)
		return nil, GraphNeedsResult{}, err
	}
	if args.Package == "" {
		err := fmt.Errorf("package name is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "graph_needs", time.Since(startTime).Seconds(), false)
		return nil, GraphNeedsResult{}, err
	}

	span.SetAttributes(
		otel.AttrTargetPath.String(args.Path),
		otel.AttrMCPGraphPackage.String(args.Package),
	)

	// Build proto request with graph enabled
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: args.Path,
		Options: &scanv1.ScanOptions{
			Ecosystems: args.Ecosystems,
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_DIR,
			},
			GraphOptions: &scanv1.GraphOptions{
				Enabled: true,
			},
		},
	})

	resp, err := s.clients.Vulns.Scan(ctx, scanReq)
	if err != nil {
		err = fmt.Errorf("scan failed: %w", err)
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "graph_needs", time.Since(startTime).Seconds(), false)
		logs.Warn(ctx, "Graph needs failed", "path", args.Path, "package", args.Package, "error", err)
		return nil, GraphNeedsResult{}, err
	}

	// Convert proto response to internal types for graph analysis
	scanResult := internalproto.ScanningResultFromProto(resp.Msg)

	// Build graph from inventory if not already built
	depGraph := scanResult.Graph
	if depGraph == nil {
		depGraph = graph.FromInventory(scanResult.Packages, scanResult.Direct)
	}

	// Find best matching node
	match := findBestMatchingNode(depGraph, args.Package)
	if match == nil {
		span.SetAttributes(otel.AttrMCPGraphFound.Bool(false))
		otel.SetSpanOK(span)
		otel.RecordMCPToolCall(ctx, "graph_needs", time.Since(startTime).Seconds(), true)
		logs.Debug(ctx, "MCP tool completed", "tool", "graph_needs", "package", args.Package, "found", false)
		return nil, GraphNeedsResult{
			Package: args.Package,
			Found:   false,
		}, nil
	}

	result := GraphNeedsResult{
		Package: match.Name,
		Version: match.Version,
		PURL:    match.PURL,
		Found:   true,
	}

	// Collect ancestors (packages that depend on this one)
	for ancestor := range depGraph.Ancestors(match.PURL) {
		dep := DependencyInfo{
			Name:      ancestor.Name,
			Version:   ancestor.Version,
			Ecosystem: ancestor.Ecosystem,
			PURL:      ancestor.PURL,
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

	// If no ancestors, check direct parents via edges
	if len(result.Dependents) == 0 {
		for parent := range depGraph.Parents(match.PURL) {
			dep := DependencyInfo{
				Name:      parent.Name,
				Version:   parent.Version,
				Ecosystem: parent.Ecosystem,
				PURL:      parent.PURL,
				Direct:    parent.Direct,
				Locations: parent.Locations,
			}
			result.Dependents = append(result.Dependents, dep)
			if parent.Direct {
				result.DirectCount++
			} else {
				result.TransitiveCount++
			}
		}
	}

	span.SetAttributes(
		otel.AttrMCPGraphFound.Bool(true),
		attribute.Int("deputy.mcp.dependent_count", len(result.Dependents)),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "graph_needs", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "graph_needs", "package", args.Package, "found", true, "dependents", len(result.Dependents))

	return nil, result, nil
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

	span.SetAttributes(otel.AttrTargetPath.String(args.Path))

	// Build proto request
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: args.Path,
		Options: &scanv1.ScanOptions{
			Ecosystems: args.Ecosystems,
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
		logs.Warn(ctx, "Triage scan failed", "path", args.Path, "error", err)
		return nil, TriageResult{}, err
	}

	// Convert proto response to internal types
	scanResult := internalproto.ScanningResultFromProto(resp.Msg)

	result := TriageResult{
		Path:            args.Path,
		Vulnerabilities: make([]TriagedVuln, 0),
		Recommendations: make([]string, 0),
	}

	// Consolidate vulnerabilities
	consolidated := vulnerability.ConsolidateAll(scanResult.Findings, scanResult.Advisories)

	// Process each vulnerability
	for _, v := range consolidated.Vulnerabilities {
		hasFix := len(v.FixedVersions) > 0
		severity := strings.ToUpper(v.Severity)
		if severity == "" {
			severity = "UNKNOWN"
		}

		// Determine priority based on severity, fixability, and direct dependency
		priority, reason := calculatePriority(severity, hasFix, v.IsDirect)

		triaged := TriagedVuln{
			ID:             v.PrimaryID,
			Severity:       severity,
			Package:        v.Package,
			Version:        v.Version,
			IsDirect:       v.IsDirect,
			HasFix:         hasFix,
			FixedVersions:  v.FixedVersions,
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
		}

		if hasFix {
			result.FixableCount++
		} else {
			result.UnfixableCount++
		}

		if v.IsDirect {
			result.DirectVulns++
		} else {
			result.TransitiveVulns++
		}
	}

	result.TotalVulns = len(consolidated.Vulnerabilities)

	// Sort by priority (critical first)
	sortTriagedVulns(result.Vulnerabilities)

	// Generate recommendations
	result.Recommendations = generateRecommendations(result)

	span.SetAttributes(
		otel.AttrMCPTriageCount.Int(result.TotalVulns),
		attribute.Int("deputy.mcp.critical_count", result.CriticalCount),
		attribute.Int("deputy.mcp.fixable_count", result.FixableCount),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "triage_vulnerabilities", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "triage_vulnerabilities", "path", args.Path, "total", result.TotalVulns, "critical", result.CriticalCount, "fixable", result.FixableCount)

	return nil, result, nil
}

// calculatePriority determines the priority of a vulnerability.
func calculatePriority(severity string, hasFix, isDirect bool) (string, string) {
	if severity == "CRITICAL" && hasFix && isDirect {
		return "critical", "Critical severity, fixable, in direct dependency"
	}
	if severity == "CRITICAL" && hasFix {
		return "critical", "Critical severity with fix available"
	}
	if severity == "CRITICAL" {
		return "high", "Critical severity but no fix available"
	}
	if severity == "HIGH" && hasFix && isDirect {
		return "high", "High severity, fixable, in direct dependency"
	}
	if severity == "HIGH" && hasFix {
		return "high", "High severity with fix available"
	}
	if severity == "HIGH" {
		return "medium", "High severity but no fix available"
	}
	if severity == "MEDIUM" && hasFix && isDirect {
		return "medium", "Medium severity, fixable, in direct dependency"
	}
	if severity == "MEDIUM" {
		return "low", "Medium severity"
	}
	return "low", "Low severity or unknown"
}

// sortTriagedVulns sorts vulnerabilities by priority.
func sortTriagedVulns(vulns []TriagedVuln) {
	priorityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	for i := 0; i < len(vulns); i++ {
		for j := i + 1; j < len(vulns); j++ {
			if priorityOrder[vulns[j].Priority] < priorityOrder[vulns[i].Priority] {
				vulns[i], vulns[j] = vulns[j], vulns[i]
			}
		}
	}
}

// generateRecommendations creates actionable recommendations from triage results.
func generateRecommendations(result TriageResult) []string {
	var recs []string

	if result.CriticalCount > 0 {
		recs = append(recs, fmt.Sprintf("Address %d critical vulnerability(ies) immediately", result.CriticalCount))
	}
	if result.DirectVulns > 0 && result.FixableCount > 0 {
		recs = append(recs, fmt.Sprintf("Update direct dependencies to fix %d vulnerability(ies)", min(result.DirectVulns, result.FixableCount)))
	}
	if result.TransitiveVulns > 0 {
		recs = append(recs, fmt.Sprintf("Review %d transitive dependency vulnerability(ies) - may require updating direct dependencies", result.TransitiveVulns))
	}
	if result.UnfixableCount > 0 {
		recs = append(recs, fmt.Sprintf("Monitor %d vulnerability(ies) without fixes for updates", result.UnfixableCount))
	}
	if result.TotalVulns == 0 {
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

	if args.Image == "" {
		err := fmt.Errorf("image is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "scan_container", time.Since(startTime).Seconds(), false)
		return nil, ContainerScanResult{}, err
	}

	span.SetAttributes(otel.AttrMCPImage.String(args.Image))

	// Build proto request for container image scan
	scanReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: args.Image,
		Options: &scanv1.ScanOptions{
			Platform: args.Platform,
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
		logs.Warn(ctx, "Container scan failed", "image", args.Image, "error", err)
		return nil, ContainerScanResult{}, err
	}

	scanResult := resp.Msg
	result := ContainerScanResult{
		Image:           args.Image,
		Platform:        args.Platform,
		PackagesScanned: int(scanResult.PackagesScanned),
		VulnerabilitiesBy: map[string]int{
			"critical": int(scanResult.Stats.GetCritical()),
			"high":     int(scanResult.Stats.GetHigh()),
			"medium":   int(scanResult.Stats.GetMedium()),
			"low":      int(scanResult.Stats.GetLow()),
		},
		Vulnerabilities: make([]VulnExplanation, 0),
		Clean:           scanResult.Stats.GetUnique() == 0,
		ScanTime:        time.Since(startTime).String(),
	}

	// Convert findings to explanations
	seen := make(map[string]bool)
	for _, finding := range scanResult.Findings {
		if seen[finding.AdvisoryId] {
			continue
		}
		seen[finding.AdvisoryId] = true

		advisory, ok := scanResult.Advisories[finding.AdvisoryId]
		if !ok {
			continue
		}
		result.Vulnerabilities = append(result.Vulnerabilities, VulnExplanation{
			ID:            advisory.Id,
			Aliases:       advisory.Aliases,
			Summary:       advisory.Summary,
			Details:       advisory.Details,
			Severity:      advisory.Severity.GetLevel().String(),
			FixedVersions: advisory.FixedVersions,
			References:    advisory.References,
		})
	}

	span.SetAttributes(
		otel.AttrMCPPackageCount.Int(int(scanResult.PackagesScanned)),
		otel.AttrMCPVulnCount.Int(int(scanResult.Stats.GetUnique())),
	)
	otel.SetSpanOK(span)
	otel.RecordMCPToolCall(ctx, "scan_container", time.Since(startTime).Seconds(), true)
	logs.Debug(ctx, "MCP tool completed", "tool", "scan_container", "image", args.Image, "packages", result.PackagesScanned, "vulns", scanResult.Stats.GetUnique(), "clean", result.Clean)

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

	if args.BaseRef == "" {
		err := fmt.Errorf("base_ref is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "diff_refs", time.Since(startTime).Seconds(), false)
		return nil, DiffRefsResult{}, err
	}
	if args.TargetRef == "" {
		err := fmt.Errorf("target_ref is required")
		otel.SetSpanError(span, err)
		otel.RecordMCPToolCall(ctx, "diff_refs", time.Since(startTime).Seconds(), false)
		return nil, DiffRefsResult{}, err
	}

	span.SetAttributes(
		otel.AttrMCPBaseRef.String(args.BaseRef),
		otel.AttrMCPTargetRef.String(args.TargetRef),
	)

	// Check if this looks like a container image diff
	isContainerDiff := isContainerImageRef(args.BaseRef) && isContainerImageRef(args.TargetRef)

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
	// Scan base image
	baseReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: args.BaseRef,
		Options: &scanv1.ScanOptions{
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE,
			},
		},
	})
	baseResp, err := s.clients.Vulns.Scan(ctx, baseReq)
	if err != nil {
		return nil, DiffRefsResult{}, fmt.Errorf("failed to scan base image %s: %w", args.BaseRef, err)
	}

	// Scan target image
	targetReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: args.TargetRef,
		Options: &scanv1.ScanOptions{
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE,
			},
		},
	})
	targetResp, err := s.clients.Vulns.Scan(ctx, targetReq)
	if err != nil {
		return nil, DiffRefsResult{}, fmt.Errorf("failed to scan target image %s: %w", args.TargetRef, err)
	}

	baseScan := baseResp.Msg
	targetScan := targetResp.Msg

	result := DiffRefsResult{
		Path:            args.BaseRef,
		BaseRef:         args.BaseRef,
		TargetRef:       args.TargetRef,
		IsContainerDiff: true,
		Changes:         make([]DependencyChange, 0),
		VulnSummary:     make(map[string]int),
	}

	// Build package maps for comparison
	basePackages := make(map[string]*PackageInfo)
	for _, pkg := range baseScan.Packages {
		key := pkg.Name + "@" + pkg.Ecosystem
		basePackages[key] = &PackageInfo{Name: pkg.Name, Version: pkg.Version, Ecosystem: pkg.Ecosystem}
	}

	targetPackages := make(map[string]*PackageInfo)
	for _, pkg := range targetScan.Packages {
		key := pkg.Name + "@" + pkg.Ecosystem
		targetPackages[key] = &PackageInfo{Name: pkg.Name, Version: pkg.Version, Ecosystem: pkg.Ecosystem}
	}

	// Find added and updated packages
	for key, targetPkg := range targetPackages {
		basePkg, exists := basePackages[key]
		if !exists {
			result.Changes = append(result.Changes, DependencyChange{
				Name:          targetPkg.Name,
				TargetVersion: targetPkg.Version,
				ChangeType:    "added",
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
				ChangeType:    changeType,
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
				ChangeType:  "removed",
				Ecosystem:   basePkg.Ecosystem,
			})
			result.RemovedCount++
		}
	}

	// Add vulnerability summary from target
	result.VulnSummary["critical"] = int(targetScan.Stats.GetCritical())
	result.VulnSummary["high"] = int(targetScan.Stats.GetHigh())
	result.VulnSummary["medium"] = int(targetScan.Stats.GetMedium())
	result.VulnSummary["low"] = int(targetScan.Stats.GetLow())

	return nil, result, nil
}

// diffGitRefs compares dependencies between Git references.
func (s *Server) diffGitRefs(ctx context.Context, args DiffRefsInput) (*mcp.CallToolResult, DiffRefsResult, error) {
	if args.Path == "" {
		return nil, DiffRefsResult{}, fmt.Errorf("path is required for Git ref comparison")
	}

	// Scan base ref
	baseReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: args.Path,
		Options: &scanv1.ScanOptions{
			Ecosystems: args.Ecosystems,
			Ref:        args.BaseRef,
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_GIT,
			},
		},
	})
	baseResp, err := s.clients.Vulns.Scan(ctx, baseReq)
	if err != nil {
		return nil, DiffRefsResult{}, fmt.Errorf("failed to scan base ref %s: %w", args.BaseRef, err)
	}

	// Scan target ref
	targetReq := connect.NewRequest(&scanv1.ScanRequest{
		Target: args.Path,
		Options: &scanv1.ScanOptions{
			Ecosystems: args.Ecosystems,
			Ref:        args.TargetRef,
			TargetHint: &scanv1.TargetHint{
				Kind: targetv1.TargetKind_TARGET_KIND_GIT,
			},
		},
	})
	targetResp, err := s.clients.Vulns.Scan(ctx, targetReq)
	if err != nil {
		return nil, DiffRefsResult{}, fmt.Errorf("failed to scan target ref %s: %w", args.TargetRef, err)
	}

	baseScan := baseResp.Msg
	targetScan := targetResp.Msg

	result := DiffRefsResult{
		Path:            args.Path,
		BaseRef:         args.BaseRef,
		TargetRef:       args.TargetRef,
		IsContainerDiff: false,
		Changes:         make([]DependencyChange, 0),
		VulnSummary:     make(map[string]int),
	}

	// Build package maps for comparison
	basePackages := make(map[string]*PackageInfo)
	for _, pkg := range baseScan.Packages {
		key := pkg.Name + "@" + pkg.Ecosystem
		basePackages[key] = &PackageInfo{Name: pkg.Name, Version: pkg.Version, Ecosystem: pkg.Ecosystem}
	}

	targetPackages := make(map[string]*PackageInfo)
	for _, pkg := range targetScan.Packages {
		key := pkg.Name + "@" + pkg.Ecosystem
		targetPackages[key] = &PackageInfo{Name: pkg.Name, Version: pkg.Version, Ecosystem: pkg.Ecosystem, Direct: pkg.Direct}
	}

	// Find added and updated packages
	for key, targetPkg := range targetPackages {
		basePkg, exists := basePackages[key]
		if !exists {
			result.Changes = append(result.Changes, DependencyChange{
				Name:          targetPkg.Name,
				TargetVersion: targetPkg.Version,
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
				ChangeType:  "removed",
				Ecosystem:   basePkg.Ecosystem,
			})
			result.RemovedCount++
		}
	}

	// Add vulnerability summary from target
	result.VulnSummary["critical"] = int(targetScan.Stats.GetCritical())
	result.VulnSummary["high"] = int(targetScan.Stats.GetHigh())
	result.VulnSummary["medium"] = int(targetScan.Stats.GetMedium())
	result.VulnSummary["low"] = int(targetScan.Stats.GetLow())

	return nil, result, nil
}

// isContainerImageRef checks if a reference looks like a container image.
func isContainerImageRef(ref string) bool {
	// Check for explicit container schemes
	if strings.HasPrefix(ref, "docker://") ||
		strings.HasPrefix(ref, "docker-daemon://") ||
		strings.HasPrefix(ref, "oci://") ||
		strings.HasPrefix(ref, "container://") {
		return true
	}

	// Check for common image patterns (registry/repo:tag or repo:tag)
	// Must contain a colon (for tag) and likely a slash (for repo path)
	// or be a well-known image like nginx:1.25
	if strings.Contains(ref, ":") {
		parts := strings.Split(ref, ":")
		if len(parts) == 2 {
			name := parts[0]
			tag := parts[1]
			// Looks like image:tag if tag is not empty and name looks like an image path
			if tag != "" && (strings.Contains(name, "/") || strings.Contains(name, ".") || isCommonBaseImage(name)) {
				return true
			}
		}
	}

	return false
}

// isCommonBaseImage checks if name is a common Docker base image.
func isCommonBaseImage(name string) bool {
	common := []string{"alpine", "nginx", "ubuntu", "debian", "centos", "fedora", "busybox", "python", "node", "golang", "rust", "redis", "postgres", "mysql", "mongo"}
	nameLower := strings.ToLower(name)
	for _, img := range common {
		if nameLower == img {
			return true
		}
	}
	return false
}

// compareVersions does a simple version comparison.
// Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
func compareVersions(v1, v2 string) int {
	// Simple string comparison - works for most semver
	if v1 < v2 {
		return -1
	}
	if v1 > v2 {
		return 1
	}
	return 0
}

// PackageInfo holds package information for diff comparison.
type PackageInfo struct {
	Name      string
	Version   string
	Ecosystem string
	Direct    bool
}

// === Graph Helper Functions ===

// findMatchingNodes finds nodes matching the query with ranked matching.
func findMatchingNodes(g *graph.Graph, query string) []*graph.Node {
	queryLower := strings.ToLower(query)

	type rankedMatch struct {
		node *graph.Node
		rank int
	}

	var matches []rankedMatch

	for node := range g.Nodes() {
		nameLower := strings.ToLower(node.Name)
		rank := 0

		// Check for exact match first (highest priority)
		if nameLower == queryLower {
			rank = 4
		} else if strings.HasSuffix(nameLower, "-"+queryLower) {
			// Hyphen suffix: go-yaml matches "yaml"
			rank = 3
		} else if strings.HasSuffix(nameLower, "/"+queryLower) {
			// Path suffix: golang.org/x/net matches "net"
			rank = 2
		} else if strings.Contains(nameLower, "/"+queryLower+".") || strings.Contains(nameLower, "/"+queryLower+"/") {
			// Path segment: gopkg.in/yaml.v3 matches "yaml"
			rank = 2
		}

		if rank > 0 {
			matches = append(matches, rankedMatch{node: node, rank: rank})
		}
	}

	// Sort by rank (highest first), then by name for determinism
	for i := 0; i < len(matches); i++ {
		for j := i + 1; j < len(matches); j++ {
			if matches[j].rank > matches[i].rank ||
				(matches[j].rank == matches[i].rank && matches[j].node.Name < matches[i].node.Name) {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}

	// Extract just the nodes
	result := make([]*graph.Node, len(matches))
	for i, m := range matches {
		result[i] = m.node
	}

	return result
}

// findBestMatchingNode finds the single best matching node for a query.
func findBestMatchingNode(g *graph.Graph, query string) *graph.Node {
	matches := findMatchingNodes(g, query)
	if len(matches) == 0 {
		return nil
	}
	return matches[0]
}

// === Helper Functions ===

// extractSeverity extracts the severity from an OSV vulnerability.
func extractSeverity(vuln *osvschema.Vulnerability) *vulnerabilityv1.Severity {
	if vuln == nil {
		return &vulnerabilityv1.Severity{}
	}

	for _, sev := range vuln.Severity {
		if sev.Score != "" {
			return vulnerability.NewSeverity(sev.Score, string(sev.Type))
		}
	}

	if vuln.DatabaseSpecific != nil {
		if sevRaw, ok := vuln.DatabaseSpecific["severity"]; ok {
			if sevStr, ok := sevRaw.(string); ok {
				return vulnerability.NewSeverity(strings.ToUpper(sevStr), "GHSA")
			}
		}
	}

	return &vulnerabilityv1.Severity{}
}

// pathToStrings converts a graph.Path to a slice of node names.
func pathToStrings(path graph.Path) []string {
	result := make([]string, len(path))
	for i, node := range path {
		result[i] = fmt.Sprintf("%s@%s", node.Name, node.Version)
	}
	return result
}
