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

	"connectrpc.com/connect"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	policyv1 "github.com/picatz/deputy/gen/deputy/policy/v1"
	remediationv1 "github.com/picatz/deputy/gen/deputy/remediation/v1"
	sbomv1 "github.com/picatz/deputy/gen/deputy/sbom/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/client"
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
	inner client.Client
}

// NewClient creates a new Deputy client with automatic mode detection.
//
// The client will automatically select the best connection mode:
//   - Remote if DEPUTY_SERVER environment variable is set
//   - Local daemon if a daemon socket exists and is responsive
//   - In-process otherwise (default)
//
// Use NewClientWithOptions for more control over the connection mode.
func NewClient(ctx context.Context) (*Client, error) {
	c, err := client.New(ctx, client.Options{})
	if err != nil {
		return nil, err
	}
	return &Client{inner: c}, nil
}

// NewClientWithOptions creates a new Deputy client with explicit options.
func NewClientWithOptions(ctx context.Context, opts Options) (*Client, error) {
	c, err := client.New(ctx, client.Options{
		Mode:          client.Mode(opts.Mode),
		ForceMode:     opts.ForceMode,
		ServerAddress: opts.ServerAddress,
		DaemonSocket:  opts.DaemonSocket,
	})
	if err != nil {
		return nil, err
	}
	return &Client{inner: c}, nil
}

// ConnectToServer creates a client connected to a remote Deputy server.
//
// Example:
//
//	client, err := sdk.ConnectToServer(ctx, "https://deputy.example.com:8090")
func ConnectToServer(ctx context.Context, addr string) (*Client, error) {
	return NewClientWithOptions(ctx, Options{
		Mode:          ModeRemote,
		ForceMode:     true,
		ServerAddress: addr,
	})
}

// ConnectToDaemon creates a client connected to a local Deputy daemon.
// If socket is empty, uses the default socket path.
//
// Example:
//
//	client, err := sdk.ConnectToDaemon(ctx, "")  // default socket
func ConnectToDaemon(ctx context.Context, socket string) (*Client, error) {
	return NewClientWithOptions(ctx, Options{
		Mode:         ModeLocalDaemon,
		ForceMode:    true,
		DaemonSocket: socket,
	})
}

// Close releases any resources held by the client.
func (c *Client) Close() error {
	return c.inner.Close()
}

// Mode returns the current client connection mode.
func (c *Client) Mode() Mode {
	return Mode(c.inner.Mode())
}

// --- Scan Operations ---

// Scan performs a vulnerability scan on a target.
// The target can be a local directory path, git ref, or remote repository.
func (c *Client) Scan(ctx context.Context, target string) (*ScanResponse, error) {
	resp, err := c.inner.Scan(ctx, connect.NewRequest(&scanv1.ScanRequest{
		Target: target,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// ScanWithOptions performs a vulnerability scan with additional options.
func (c *Client) ScanWithOptions(ctx context.Context, target string, opts *ScanOptions) (*ScanResponse, error) {
	resp, err := c.inner.Scan(ctx, connect.NewRequest(&scanv1.ScanRequest{
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
	stream, err := c.inner.StreamScan(ctx, connect.NewRequest(&scanv1.StreamScanRequest{
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
	resp, err := c.inner.ListPackages(ctx, connect.NewRequest(&listv1.ListPackagesRequest{
		Target: target,
	}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// ListEcosystems lists all supported package ecosystems.
func (c *Client) ListEcosystems(ctx context.Context) (*listv1.ListEcosystemsResponse, error) {
	resp, err := c.inner.ListEcosystems(ctx, connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

// --- SBOM Operations ---

// GenerateSBOM generates a Software Bill of Materials for a target.
func (c *Client) GenerateSBOM(ctx context.Context, target string, format sbomv1.Format) (*sbomv1.GenerateResponse, error) {
	resp, err := c.inner.GenerateSBOM(ctx, connect.NewRequest(&sbomv1.GenerateRequest{
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
	resp, err := c.inner.DiffSBOM(ctx, connect.NewRequest(&sbomv1.DiffRequest{
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
	resp, err := c.inner.ListAgents(ctx, connect.NewRequest(&remediationv1.ListAgentsRequest{}))
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
	// If empty, uses the default location.
	DaemonSocket string
}

// Mode indicates how the client connects to Deputy services.
type Mode int

const (
	// ModeInProcess uses direct function calls (default, zero network overhead).
	ModeInProcess Mode = iota

	// ModeLocalDaemon connects via Unix socket to a local daemon.
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
	stream client.Stream[scanv1.ScanProgress]
}

// Receive returns the next progress update.
// Returns io.EOF when the stream is complete.
func (s *ScanStream) Receive() (*ScanProgress, error) {
	return s.stream.Receive()
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
		progress, err := s.stream.Receive()
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
