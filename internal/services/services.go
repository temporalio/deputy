package services

import (
	"net/http"

	"connectrpc.com/connect"

	"github.com/picatz/deputy/gen/deputy/diff/v1/diffv1connect"
	"github.com/picatz/deputy/gen/deputy/graph/v1/graphv1connect"
	"github.com/picatz/deputy/gen/deputy/list/v1/listv1connect"
	"github.com/picatz/deputy/gen/deputy/remediation/v1/remediationv1connect"
	"github.com/picatz/deputy/gen/deputy/sbom/v1/sbomv1connect"
	"github.com/picatz/deputy/gen/deputy/scan/v1/scanv1connect"
	"github.com/picatz/deputy/gen/deputy/secrets/v1/secretsv1connect"
	"github.com/picatz/deputy/internal/server"
)

// Services holds all Deputy service handlers.
//
// These handlers implement the ConnectRPC generated interfaces and can be:
//   - Mounted as HTTP handlers for the server
//   - Used directly via InProcessTransport for CLI/MCP
//   - Exposed via pluginrpc for plugin extensibility
type Services struct {
	Scan        scanv1connect.ScanServiceHandler
	List        listv1connect.ListServiceHandler
	SBOM        sbomv1connect.SBOMServiceHandler
	Secrets     secretsv1connect.SecretsServiceHandler
	Diff        diffv1connect.DiffServiceHandler
	Graph       graphv1connect.GraphServiceHandler
	Remediation remediationv1connect.RemediationServiceHandler
}

// Config configures service creation.
type Config struct {
	// Scanner is the shared scan service. If nil, defaults are created.
	Scanner interface{} // *scan.Service - using interface{} to avoid import cycle

	// LocalMode enables local mode which skips remote target validation.
	// Use this for in-process clients that need to access local filesystems.
	LocalMode bool
}

// New creates a new Services with default configuration (local mode enabled).
func New() (*Services, error) {
	return NewWithConfig(Config{LocalMode: true})
}

// NewForServer creates Services configured for remote server mode.
// This enables security validation that rejects local filesystem paths.
func NewForServer() (*Services, error) {
	return NewWithConfig(Config{LocalMode: false})
}

// NewWithConfig creates a new Services with the given configuration.
func NewWithConfig(cfg Config) (*Services, error) {
	// Create secrets handler (can fail)
	secretsHandler, err := server.NewSecretsHandler()
	if err != nil {
		return nil, err
	}

	if cfg.LocalMode {
		return &Services{
			Scan:        server.NewScanHandler(nil, server.WithLocalMode()),
			List:        server.NewListHandler(nil, server.WithListLocalMode()),
			SBOM:        server.NewSBOMHandler(),
			Secrets:     secretsHandler,
			Diff:        server.NewDiffHandler(nil, server.WithDiffLocalMode()),
			Graph:       server.NewGraphHandler(),
			Remediation: server.NewRemediationHandler(),
		}, nil
	}

	return &Services{
		Scan:        server.NewScanHandler(nil),
		List:        server.NewListHandler(nil),
		SBOM:        server.NewSBOMHandler(),
		Secrets:     secretsHandler,
		Diff:        server.NewDiffHandler(nil),
		Graph:       server.NewGraphHandler(),
		Remediation: server.NewRemediationHandler(),
	}, nil
}

// RegisterHandlers mounts all service handlers on the given mux.
// Returns the list of registered path prefixes.
func (s *Services) RegisterHandlers(mux *http.ServeMux, opts ...connect.HandlerOption) []string {
	var paths []string

	path, handler := scanv1connect.NewScanServiceHandler(s.Scan, opts...)
	mux.Handle(path, handler)
	paths = append(paths, path)

	path, handler = listv1connect.NewListServiceHandler(s.List, opts...)
	mux.Handle(path, handler)
	paths = append(paths, path)

	path, handler = sbomv1connect.NewSBOMServiceHandler(s.SBOM, opts...)
	mux.Handle(path, handler)
	paths = append(paths, path)

	path, handler = secretsv1connect.NewSecretsServiceHandler(s.Secrets, opts...)
	mux.Handle(path, handler)
	paths = append(paths, path)

	path, handler = diffv1connect.NewDiffServiceHandler(s.Diff, opts...)
	mux.Handle(path, handler)
	paths = append(paths, path)

	path, handler = graphv1connect.NewGraphServiceHandler(s.Graph, opts...)
	mux.Handle(path, handler)
	paths = append(paths, path)

	path, handler = remediationv1connect.NewRemediationServiceHandler(s.Remediation, opts...)
	mux.Handle(path, handler)
	paths = append(paths, path)

	return paths
}

// Clients holds generated ConnectRPC client interfaces.
// These can be used by CLI, MCP, and other consumers.
//
// Field names are chosen to minimize "type stuttering" in calls:
//   - c.Vulns.Scan() instead of c.Scan.Scan()
//   - c.Inventory.ListPackages() instead of c.List.ListPackages()
type Clients struct {
	Vulns       scanv1connect.ScanServiceClient       // Vulnerability scanning
	Inventory   listv1connect.ListServiceClient       // Package enumeration
	SBOM        sbomv1connect.SBOMServiceClient       // SBOM generation
	Secrets     secretsv1connect.SecretsServiceClient // Secret detection
	Diff        diffv1connect.DiffServiceClient       // Diff comparisons
	Graph       graphv1connect.GraphServiceClient     // Dependency graphs
	Remediation remediationv1connect.RemediationServiceClient
}

// InProcessClients creates clients that call handlers directly without network overhead.
// This is the recommended way to use services in CLI and MCP contexts.
func (s *Services) InProcessClients(opts ...connect.ClientOption) *Clients {
	// Create a mux and register handlers
	mux := http.NewServeMux()
	s.RegisterHandlers(mux)

	// Create transport that routes to handlers
	transport := NewInProcessTransport(mux)
	httpClient := transport.HTTPClient()

	// Empty base URL since we're not making real network calls
	baseURL := ""

	return &Clients{
		Vulns:       scanv1connect.NewScanServiceClient(httpClient, baseURL, opts...),
		Inventory:   listv1connect.NewListServiceClient(httpClient, baseURL, opts...),
		SBOM:        sbomv1connect.NewSBOMServiceClient(httpClient, baseURL, opts...),
		Secrets:     secretsv1connect.NewSecretsServiceClient(httpClient, baseURL, opts...),
		Diff:        diffv1connect.NewDiffServiceClient(httpClient, baseURL, opts...),
		Graph:       graphv1connect.NewGraphServiceClient(httpClient, baseURL, opts...),
		Remediation: remediationv1connect.NewRemediationServiceClient(httpClient, baseURL, opts...),
	}
}

// RemoteClients creates clients that connect to a remote server.
func RemoteClients(httpClient connect.HTTPClient, baseURL string, opts ...connect.ClientOption) *Clients {
	return &Clients{
		Vulns:       scanv1connect.NewScanServiceClient(httpClient, baseURL, opts...),
		Inventory:   listv1connect.NewListServiceClient(httpClient, baseURL, opts...),
		SBOM:        sbomv1connect.NewSBOMServiceClient(httpClient, baseURL, opts...),
		Secrets:     secretsv1connect.NewSecretsServiceClient(httpClient, baseURL, opts...),
		Diff:        diffv1connect.NewDiffServiceClient(httpClient, baseURL, opts...),
		Graph:       graphv1connect.NewGraphServiceClient(httpClient, baseURL, opts...),
		Remediation: remediationv1connect.NewRemediationServiceClient(httpClient, baseURL, opts...),
	}
}

