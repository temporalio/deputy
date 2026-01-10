// Package sdk provides a simple Go SDK for the Deputy vulnerability scanner.
//
// The SDK provides a unified API that works transparently in three modes:
//   - In-process: Direct function calls (default, zero network overhead)
//   - Local daemon: Via Unix socket to a local deputy server
//   - Remote: Via HTTP/2 to a remote deputy server
//
// Mode selection is automatic based on environment:
//   - If DEPUTY_SERVER is set, uses remote mode
//   - If a local daemon socket exists, uses daemon mode
//   - Otherwise, uses in-process mode
//
// Basic usage:
//
//	import "github.com/picatz/deputy/sdk"
//
//	client, err := sdk.NewClient(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Scan current directory
//	result, err := client.Scan(ctx, ".")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Found %d findings\n", len(result.GetFindings()))
package sdk

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"

	"connectrpc.com/connect"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	diffv1 "github.com/picatz/deputy/gen/deputy/diff/v1"
	graphv1 "github.com/picatz/deputy/gen/deputy/graph/v1"
	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	policyv1 "github.com/picatz/deputy/gen/deputy/policy/v1"
	remediationv1 "github.com/picatz/deputy/gen/deputy/remediation/v1"
	sbomv1 "github.com/picatz/deputy/gen/deputy/sbom/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	secretsv1 "github.com/picatz/deputy/gen/deputy/secrets/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/services"
)

// Re-export commonly used proto types for convenience.
// These allow users to work with scan results without importing multiple packages.
type (
	// ScanResponse is the result of a vulnerability scan.
	ScanResponse = scanv1.ScanResponse

	// ScanOptions configure scan behavior.
	ScanOptions = scanv1.ScanOptions

	// ScanProgress represents streaming scan progress.
	ScanProgress = scanv1.ScanProgress

	// Finding represents a vulnerability found in a package.
	Finding = vulnerabilityv1.Finding

	// Advisory contains vulnerability advisory details.
	Advisory = vulnerabilityv1.Advisory

	// Package represents a discovered dependency.
	Package = dependencyv1.Package

	// PolicyAction represents a policy evaluation outcome.
	PolicyAction = policyv1.Action

	// AgentInfo describes an available AI agent.
	AgentInfo = remediationv1.AgentInfo
)

// Client is the Deputy SDK client.
type Client struct {
	clients *services.Clients
	mode    Mode
}

// DefaultDaemonSocket is the default Unix socket path for the local daemon.
const DefaultDaemonSocket = "/tmp/deputy.sock"

// NewClient creates a new Deputy client with automatic mode detection.
//
// The client will automatically select the best connection mode:
//   - Remote if DEPUTY_SERVER environment variable is set
//   - Local daemon if DEPUTY_DAEMON is set or default socket exists
//   - In-process otherwise (default)
//
// Use NewClientWithOptions for more control over the connection mode.
func NewClient(ctx context.Context) (*Client, error) {
	// Check for remote server
	if serverAddr := os.Getenv("DEPUTY_SERVER"); serverAddr != "" {
		return &Client{
			clients: services.RemoteClients(http.DefaultClient, serverAddr),
			mode:    ModeRemote,
		}, nil
	}

	// Check for local daemon
	if daemonSocket := os.Getenv("DEPUTY_DAEMON"); daemonSocket != "" {
		return connectToDaemon(daemonSocket)
	}

	// Check if default daemon socket exists
	if _, err := os.Stat(DefaultDaemonSocket); err == nil {
		return connectToDaemon(DefaultDaemonSocket)
	}

	// Default to in-process
	svc, err := services.New()
	if err != nil {
		return nil, err
	}
	return &Client{
		clients: svc.InProcessClients(),
		mode:    ModeInProcess,
	}, nil
}

// connectToDaemon creates a client connected to a local daemon via Unix socket.
func connectToDaemon(socket string) (*Client, error) {
	// Unix socket uses http:// scheme with custom transport
	return &Client{
		clients: services.RemoteClients(
			&http.Client{Transport: &unixSocketTransport{socket: socket}},
			"http://localhost",
		),
		mode: ModeLocalDaemon,
	}, nil
}

// NewClientWithOptions creates a new Deputy client with explicit options.
func NewClientWithOptions(ctx context.Context, opts Options) (*Client, error) {
	if opts.ForceMode {
		switch opts.Mode {
		case ModeRemote:
			return &Client{
				clients: services.RemoteClients(http.DefaultClient, opts.ServerAddress),
				mode:    ModeRemote,
			}, nil
		case ModeLocalDaemon:
			socket := opts.DaemonSocket
			if socket == "" {
				socket = DefaultDaemonSocket
			}
			return connectToDaemon(socket)
		default: // ModeInProcess
			svc, err := services.New()
			if err != nil {
				return nil, err
			}
			return &Client{
				clients: svc.InProcessClients(),
				mode:    ModeInProcess,
			}, nil
		}
	}

	// Auto-detect
	return NewClient(ctx)
}

// ConnectToServer creates a client connected to a remote Deputy server.
//
// Example:
//
//	client, err := sdk.ConnectToServer(ctx, "https://deputy.example.com:8090")
func ConnectToServer(ctx context.Context, addr string) (*Client, error) {
	return &Client{
		clients: services.RemoteClients(http.DefaultClient, addr),
		mode:    ModeRemote,
	}, nil
}

// ConnectToDaemon creates a client connected to a local Deputy daemon.
// If socket is empty, uses the default socket path.
//
// The daemon mode is useful for:
//   - Shared caching across multiple CLI invocations
//   - Centralized OTel collection and observability
//   - Running Deputy in a local Docker container
//
// Example:
//
//	client, err := sdk.ConnectToDaemon(ctx, "")  // default socket
//	client, err := sdk.ConnectToDaemon(ctx, "/var/run/deputy.sock")
func ConnectToDaemon(ctx context.Context, socket string) (*Client, error) {
	if socket == "" {
		socket = DefaultDaemonSocket
	}
	return connectToDaemon(socket)
}

// Close releases any resources held by the client.
func (c *Client) Close() error {
	return nil
}

// Mode returns the current client connection mode.
func (c *Client) Mode() Mode {
	return c.mode
}

// Clients returns the underlying services.Clients for advanced usage.
func (c *Client) Clients() *services.Clients {
	return c.clients
}

// --- Scan Operations ---

// Scan performs a vulnerability scan on a target.
// The target can be a local directory path, git ref, or remote repository.
func (c *Client) Scan(ctx context.Context, target string) (*ScanResponse, error) {
	resp, err := c.clients.Vulns.Scan(ctx, connect.NewRequest(&scanv1.ScanRequest{
		Target: target,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// ScanWithOptions performs a vulnerability scan with additional options.
func (c *Client) ScanWithOptions(ctx context.Context, target string, opts *ScanOptions) (*ScanResponse, error) {
	resp, err := c.clients.Vulns.Scan(ctx, connect.NewRequest(&scanv1.ScanRequest{
		Target:  target,
		Options: opts,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// StreamScan performs a scan with streaming progress updates.
// The returned stream must be closed when done.
func (c *Client) StreamScan(ctx context.Context, target string) (*ScanStream, error) {
	stream, err := c.clients.Vulns.StreamScan(ctx, connect.NewRequest(&scanv1.StreamScanRequest{
		Target: target,
	}))
	if err != nil {
		return nil, err
	}
	return &ScanStream{stream: stream}, nil
}

// --- List Operations ---

// ListPackages lists all packages in a target.
func (c *Client) ListPackages(ctx context.Context, target string) (*listv1.ListPackagesResponse, error) {
	resp, err := c.clients.Inventory.ListPackages(ctx, connect.NewRequest(&listv1.ListPackagesRequest{
		Target: target,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// ListEcosystems lists all supported package ecosystems.
func (c *Client) ListEcosystems(ctx context.Context) (*listv1.ListEcosystemsResponse, error) {
	resp, err := c.clients.Inventory.ListEcosystems(ctx, connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// --- SBOM Operations ---

// GenerateSBOM generates a Software Bill of Materials for a target.
func (c *Client) GenerateSBOM(ctx context.Context, target string, format sbomv1.Format) (*sbomv1.GenerateResponse, error) {
	resp, err := c.clients.SBOM.Generate(ctx, connect.NewRequest(&sbomv1.GenerateRequest{
		Target: target,
		Format: format,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// DiffSBOM computes differences between two SBOMs.
func (c *Client) DiffSBOM(ctx context.Context, base, target []byte) (*sbomv1.DiffResponse, error) {
	resp, err := c.clients.SBOM.Diff(ctx, connect.NewRequest(&sbomv1.DiffRequest{
		Base:   base,
		Target: target,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// --- Remediation Operations ---

// ListAgents returns available AI agents for remediation.
func (c *Client) ListAgents(ctx context.Context) (*remediationv1.ListAgentsResponse, error) {
	resp, err := c.clients.Remediation.ListAgents(ctx, connect.NewRequest(&remediationv1.ListAgentsRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// --- Graph Operations ---

// BuildGraphOptions configures dependency graph construction.
type BuildGraphOptions = graphv1.GraphOptions

// BuildGraph constructs a dependency graph for a target.
// The target can be a local directory, git repository, or container image.
//
// Example:
//
//	graph, err := client.BuildGraph(ctx, ".", nil)
//	for _, node := range graph.GetNodes() {
//	    fmt.Printf("%s@%s (depth: %d)\n", node.Name, node.Version, node.Depth)
//	}
func (c *Client) BuildGraph(ctx context.Context, target string, opts *BuildGraphOptions) (*graphv1.BuildGraphResponse, error) {
	resp, err := c.clients.Graph.BuildGraph(ctx, connect.NewRequest(&graphv1.BuildGraphRequest{
		Target:  target,
		Options: opts,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// WhyDependency explains why a specific dependency exists in a target.
// Returns all paths from the project root to the specified dependency.
//
// The dependency parameter can be a PURL, package name, or name@version.
//
// Example:
//
//	why, err := client.WhyDependency(ctx, ".", "golang.org/x/crypto")
//	for _, path := range why.GetPaths() {
//	    fmt.Printf("Path (length %d): ", path.Length)
//	    for _, node := range path.Nodes {
//	        fmt.Printf("%s -> ", node.Name)
//	    }
//	    fmt.Println()
//	}
func (c *Client) WhyDependency(ctx context.Context, target, dependency string) (*graphv1.WhyDependencyResponse, error) {
	resp, err := c.clients.Graph.WhyDependency(ctx, connect.NewRequest(&graphv1.WhyDependencyRequest{
		Target:     target,
		Dependency: dependency,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// --- Diff Operations ---

// DiffPackages compares package dependencies between two targets.
// Targets can be git refs, container image tags, or directory paths.
//
// Example:
//
//	diff, err := client.DiffPackages(ctx, "main", "HEAD")
//	for _, change := range diff.GetChanges() {
//	    fmt.Printf("%s: %s %s -> %s\n",
//	        change.ChangeKind, change.Package.Name,
//	        change.BaseVersion, change.TargetVersion)
//	}
func (c *Client) DiffPackages(ctx context.Context, base, target string) (*diffv1.DiffPackagesResponse, error) {
	resp, err := c.clients.Diff.DiffPackages(ctx, connect.NewRequest(&diffv1.DiffPackagesRequest{
		BaseTarget:   base,
		TargetTarget: target,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// DiffVulnerabilities compares vulnerabilities between two targets.
// This performs vulnerability scans on both targets and computes the difference.
//
// Example:
//
//	diff, err := client.DiffVulnerabilities(ctx, "v1.0.0", "v2.0.0")
//	fmt.Printf("Added: %d, Fixed: %d\n",
//	    len(diff.GetAddedVulnerabilities()),
//	    len(diff.GetRemovedVulnerabilities()))
func (c *Client) DiffVulnerabilities(ctx context.Context, base, target string) (*diffv1.DiffVulnerabilitiesResponse, error) {
	resp, err := c.clients.Diff.DiffVulnerabilities(ctx, connect.NewRequest(&diffv1.DiffVulnerabilitiesRequest{
		BaseTarget:   base,
		TargetTarget: target,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// DiffContainerImages compares two container images comprehensively.
// This includes package changes, vulnerability changes, layer analysis, and config changes.
//
// Example:
//
//	diff, err := client.DiffContainerImages(ctx, "nginx:1.24", "nginx:1.25")
//	fmt.Printf("Package changes: %d\n", len(diff.GetPackageChanges()))
//	if diff.Summary != nil {
//	    fmt.Printf("Size delta: %d bytes\n", diff.Summary.SizeDelta)
//	}
func (c *Client) DiffContainerImages(ctx context.Context, base, target string) (*diffv1.DiffContainerImagesResponse, error) {
	resp, err := c.clients.Diff.DiffContainerImages(ctx, connect.NewRequest(&diffv1.DiffContainerImagesRequest{
		BaseImage:   base,
		TargetImage: target,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// --- Secrets Operations ---

// ScanSecretsOptions configures secret scanning behavior.
type ScanSecretsOptions = secretsv1.ScanOptions

// ScanSecrets scans a target for secrets and sensitive data.
// The target can be a directory, git repository, or container image.
//
// Example:
//
//	result, err := client.ScanSecrets(ctx, ".", nil)
//	for _, finding := range result.GetFindings() {
//	    fmt.Printf("%s: %s in %s:%d\n",
//	        finding.DetectorId, finding.Description,
//	        finding.Location.Path, finding.Location.Line)
//	}
func (c *Client) ScanSecrets(ctx context.Context, target string, opts *ScanSecretsOptions) (*secretsv1.ScanResponse, error) {
	resp, err := c.clients.Secrets.Scan(ctx, connect.NewRequest(&secretsv1.ScanRequest{
		Target:  target,
		Options: opts,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// ListDetectors returns available secret detectors.
//
// Example:
//
//	detectors, err := client.ListDetectors(ctx)
//	for _, d := range detectors.GetDetectors() {
//	    fmt.Printf("%s: %s\n", d.Id, d.Description)
//	}
func (c *Client) ListDetectors(ctx context.Context) (*secretsv1.ListDetectorsResponse, error) {
	resp, err := c.clients.Secrets.ListDetectors(ctx, connect.NewRequest(&secretsv1.ListDetectorsRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// --- Types ---

// Options configures client creation.
//
// Zero value enables automatic mode detection (recommended default):
//
//	client, err := sdk.NewClient(ctx)
//
// For explicit control, use the convenience constructors or set fields directly:
//
//	client, err := sdk.ConnectToServer(ctx, "https://deputy.example.com:8090")
//	client, err := sdk.ConnectToDaemon(ctx, "")  // default socket
type Options struct {
	// Mode sets the connection mode. If zero and ForceMode is false,
	// mode is auto-detected.
	Mode Mode

	// ForceMode disables auto-detection and uses Mode as specified.
	ForceMode bool

	// ServerAddress is the remote server address for Mode == ModeRemote.
	// Example: "https://deputy.example.com:8090"
	ServerAddress string

	// DaemonSocket is the Unix socket path for Mode == ModeLocalDaemon.
	// If empty, uses DefaultDaemonSocket.
	DaemonSocket string
}

// Mode indicates how the client connects to Deputy services.
type Mode int

const (
	// ModeInProcess uses direct function calls (default, zero network overhead).
	ModeInProcess Mode = iota

	// ModeLocalDaemon connects via Unix socket to a local daemon.
	// Useful for shared caching, OTel collection, and local observability.
	ModeLocalDaemon

	// ModeRemote connects via HTTP/2 to a remote server.
	ModeRemote
)

// String returns the string representation of the mode.
func (m Mode) String() string {
	switch m {
	case ModeInProcess:
		return "in-process"
	case ModeLocalDaemon:
		return "local-daemon"
	case ModeRemote:
		return "remote"
	default:
		return "unknown"
	}
}

// ScanStream is a streaming scan result.
type ScanStream struct {
	stream *connect.ServerStreamForClient[scanv1.ScanProgress]
}

// Receive returns the next progress update.
// Returns io.EOF when the stream is complete.
func (s *ScanStream) Receive() (*ScanProgress, error) {
	if s.stream.Receive() {
		return s.stream.Msg(), nil
	}
	if err := s.stream.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

// Close closes the stream.
func (s *ScanStream) Close() error {
	return s.stream.Close()
}

// Collect reads all progress updates and returns the final result.
// This is a convenience method that consumes the entire stream.
func (s *ScanStream) Collect() (*ScanResponse, error) {
	defer s.Close()
	var lastProgress *scanv1.ScanProgress
	for {
		progress, err := s.Receive()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		lastProgress = progress
	}
	if lastProgress == nil || lastProgress.GetResult() == nil {
		return &ScanResponse{}, nil
	}
	return lastProgress.GetResult(), nil
}

// SBOM format constants for convenience.
const (
	SBOMFormatCycloneDXJSON = sbomv1.Format_FORMAT_CYCLONEDX_JSON
	SBOMFormatSPDXJSON      = sbomv1.Format_FORMAT_SPDX_JSON
	SBOMFormatProtobomJSON  = sbomv1.Format_FORMAT_PROTOBOM_JSON
)

// unixSocketTransport is an http.RoundTripper that connects via Unix socket.
type unixSocketTransport struct {
	socket string
}

func (t *unixSocketTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Dial Unix socket and use it for the HTTP connection
	conn, err := net.Dial("unix", t.socket)
	if err != nil {
		return nil, err
	}

	// Create HTTP client connection over the Unix socket
	clientConn := httputil.NewClientConn(conn, nil)
	defer clientConn.Close()

	return clientConn.Do(req)
}
