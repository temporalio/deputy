package client

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"

	"connectrpc.com/connect"

	diffv1 "github.com/picatz/deputy/gen/deputy/diff/v1"
	"github.com/picatz/deputy/gen/deputy/diff/v1/diffv1connect"
	graphv1 "github.com/picatz/deputy/gen/deputy/graph/v1"
	"github.com/picatz/deputy/gen/deputy/graph/v1/graphv1connect"
	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/gen/deputy/list/v1/listv1connect"
	remediationv1 "github.com/picatz/deputy/gen/deputy/remediation/v1"
	"github.com/picatz/deputy/gen/deputy/remediation/v1/remediationv1connect"
	sbomv1 "github.com/picatz/deputy/gen/deputy/sbom/v1"
	"github.com/picatz/deputy/gen/deputy/sbom/v1/sbomv1connect"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	"github.com/picatz/deputy/gen/deputy/scan/v1/scanv1connect"
	secretsv1 "github.com/picatz/deputy/gen/deputy/secrets/v1"
	"github.com/picatz/deputy/gen/deputy/secrets/v1/secretsv1connect"
)

// Remote implements Client by communicating with a Deputy server via ConnectRPC.
// This is used for both local daemon (Unix socket) and remote server (HTTP/2) modes.
type Remote struct {
	scanClient        scanv1connect.ScanServiceClient
	listClient        listv1connect.ListServiceClient
	sbomClient        sbomv1connect.SBOMServiceClient
	remediationClient remediationv1connect.RemediationServiceClient
	secretsClient     secretsv1connect.SecretsServiceClient
	diffClient        diffv1connect.DiffServiceClient
	graphClient       graphv1connect.GraphServiceClient
	httpClient        *http.Client
	addr              string
	isDaemon          bool
}

// Ensure Remote implements Client at compile time.
var _ Client = (*Remote)(nil)

// NewRemote creates a remote client that connects to a Deputy server.
// If isDaemon is true, addr is treated as a Unix socket path.
// Otherwise, addr is treated as an HTTP URL.
func NewRemote(addr string, isDaemon bool) *Remote {
	var httpClient *http.Client
	var baseURL string

	if isDaemon {
		// Unix socket transport
		httpClient = &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", addr)
				},
			},
		}
		// For Unix sockets, use a dummy HTTP URL
		baseURL = "http://localhost"
	} else {
		// HTTP transport
		httpClient = http.DefaultClient
		baseURL = addr
		if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
			baseURL = "http://" + baseURL
		}
	}

	return &Remote{
		scanClient:        scanv1connect.NewScanServiceClient(httpClient, baseURL),
		listClient:        listv1connect.NewListServiceClient(httpClient, baseURL),
		sbomClient:        sbomv1connect.NewSBOMServiceClient(httpClient, baseURL),
		remediationClient: remediationv1connect.NewRemediationServiceClient(httpClient, baseURL),
		secretsClient:     secretsv1connect.NewSecretsServiceClient(httpClient, baseURL),
		diffClient:        diffv1connect.NewDiffServiceClient(httpClient, baseURL),
		graphClient:       graphv1connect.NewGraphServiceClient(httpClient, baseURL),
		httpClient:        httpClient,
		addr:              addr,
		isDaemon:          isDaemon,
	}
}

// Scan performs a vulnerability scan on a target.
func (c *Remote) Scan(ctx context.Context, req *connect.Request[scanv1.ScanRequest]) (*connect.Response[scanv1.ScanResponse], error) {
	return c.scanClient.Scan(ctx, req)
}

// StreamScan performs a vulnerability scan with streaming progress updates.
func (c *Remote) StreamScan(ctx context.Context, req *connect.Request[scanv1.StreamScanRequest]) (Stream[scanv1.ScanProgress], error) {
	stream, err := c.scanClient.StreamScan(ctx, req)
	if err != nil {
		return nil, err
	}
	return &connectStream[scanv1.ScanProgress]{stream: stream}, nil
}

// ListPackages lists packages in a target.
func (c *Remote) ListPackages(ctx context.Context, req *connect.Request[listv1.ListPackagesRequest]) (*connect.Response[listv1.ListPackagesResponse], error) {
	return c.listClient.ListPackages(ctx, req)
}

// ListEcosystems lists supported package ecosystems.
func (c *Remote) ListEcosystems(ctx context.Context, req *connect.Request[listv1.ListEcosystemsRequest]) (*connect.Response[listv1.ListEcosystemsResponse], error) {
	return c.listClient.ListEcosystems(ctx, req)
}

// GenerateSBOM generates a Software Bill of Materials.
func (c *Remote) GenerateSBOM(ctx context.Context, req *connect.Request[sbomv1.GenerateRequest]) (*connect.Response[sbomv1.GenerateResponse], error) {
	return c.sbomClient.Generate(ctx, req)
}

// DiffSBOM computes differences between two SBOMs.
func (c *Remote) DiffSBOM(ctx context.Context, req *connect.Request[sbomv1.DiffRequest]) (*connect.Response[sbomv1.DiffResponse], error) {
	return c.sbomClient.Diff(ctx, req)
}

// ============================================================================
// Remediation Service
// ============================================================================

// GeneratePlan creates a remediation plan from scan results.
func (c *Remote) GeneratePlan(ctx context.Context, req *connect.Request[remediationv1.GeneratePlanRequest]) (*connect.Response[remediationv1.GeneratePlanResponse], error) {
	return c.remediationClient.GeneratePlan(ctx, req)
}

// ExecutePlan applies a previously generated remediation plan.
func (c *Remote) ExecutePlan(ctx context.Context, req *connect.Request[remediationv1.ExecutePlanRequest]) (Stream[remediationv1.ExecutionEvent], error) {
	stream, err := c.remediationClient.ExecutePlan(ctx, req)
	if err != nil {
		return nil, err
	}
	return &connectStream[remediationv1.ExecutionEvent]{stream: stream}, nil
}

// ExecuteWithAgent uses an AI agent to generate and apply fixes interactively.
func (c *Remote) ExecuteWithAgent(ctx context.Context, req *connect.Request[remediationv1.ExecuteWithAgentRequest]) (Stream[remediationv1.AgentEvent], error) {
	stream, err := c.remediationClient.ExecuteWithAgent(ctx, req)
	if err != nil {
		return nil, err
	}
	return &connectStream[remediationv1.AgentEvent]{stream: stream}, nil
}

// ResumeAgent resumes a previous agent execution session.
func (c *Remote) ResumeAgent(ctx context.Context, req *connect.Request[remediationv1.ResumeAgentRequest]) (Stream[remediationv1.AgentEvent], error) {
	stream, err := c.remediationClient.ResumeAgent(ctx, req)
	if err != nil {
		return nil, err
	}
	return &connectStream[remediationv1.AgentEvent]{stream: stream}, nil
}

// ListAgents returns available AI agents for remediation.
func (c *Remote) ListAgents(ctx context.Context, req *connect.Request[remediationv1.ListAgentsRequest]) (*connect.Response[remediationv1.ListAgentsResponse], error) {
	return c.remediationClient.ListAgents(ctx, req)
}

// ApproveStep approves or denies a pending remediation step.
func (c *Remote) ApproveStep(ctx context.Context, req *connect.Request[remediationv1.ApproveStepRequest]) (*connect.Response[remediationv1.ApproveStepResponse], error) {
	return c.remediationClient.ApproveStep(ctx, req)
}

// ============================================================================
// Secrets Service
// ============================================================================

// ScanSecrets performs secret detection on a target.
func (c *Remote) ScanSecrets(ctx context.Context, req *connect.Request[secretsv1.ScanRequest]) (*connect.Response[secretsv1.ScanResponse], error) {
	return c.secretsClient.Scan(ctx, req)
}

// StreamScanSecrets performs secret detection with streaming progress updates.
func (c *Remote) StreamScanSecrets(ctx context.Context, req *connect.Request[secretsv1.StreamScanRequest]) (Stream[secretsv1.ScanProgress], error) {
	stream, err := c.secretsClient.StreamScan(ctx, req)
	if err != nil {
		return nil, err
	}
	return &connectStream[secretsv1.ScanProgress]{stream: stream}, nil
}

// ScanSecretsHistory scans git history for secrets.
func (c *Remote) ScanSecretsHistory(ctx context.Context, req *connect.Request[secretsv1.ScanHistoryRequest]) (*connect.Response[secretsv1.ScanHistoryResponse], error) {
	return c.secretsClient.ScanHistory(ctx, req)
}

// ScanSecretsDiff scans changes between two git refs for secrets.
func (c *Remote) ScanSecretsDiff(ctx context.Context, req *connect.Request[secretsv1.ScanDiffRequest]) (*connect.Response[secretsv1.ScanDiffResponse], error) {
	return c.secretsClient.ScanDiff(ctx, req)
}

// VerifySecrets attempts to validate detected secrets.
func (c *Remote) VerifySecrets(ctx context.Context, req *connect.Request[secretsv1.VerifyRequest]) (*connect.Response[secretsv1.VerifyResponse], error) {
	return c.secretsClient.Verify(ctx, req)
}

// ListDetectors returns available secret detectors.
func (c *Remote) ListDetectors(ctx context.Context, req *connect.Request[secretsv1.ListDetectorsRequest]) (*connect.Response[secretsv1.ListDetectorsResponse], error) {
	return c.secretsClient.ListDetectors(ctx, req)
}

// ============================================================================
// Diff Service
// ============================================================================

// DiffPackages compares dependencies between two targets.
func (c *Remote) DiffPackages(ctx context.Context, req *connect.Request[diffv1.DiffPackagesRequest]) (*connect.Response[diffv1.DiffPackagesResponse], error) {
	return c.diffClient.DiffPackages(ctx, req)
}

// DiffVulnerabilities compares vulnerabilities between two targets.
func (c *Remote) DiffVulnerabilities(ctx context.Context, req *connect.Request[diffv1.DiffVulnerabilitiesRequest]) (*connect.Response[diffv1.DiffVulnerabilitiesResponse], error) {
	return c.diffClient.DiffVulnerabilities(ctx, req)
}

// DiffContainerImages performs a comprehensive diff between two container images.
func (c *Remote) DiffContainerImages(ctx context.Context, req *connect.Request[diffv1.DiffContainerImagesRequest]) (*connect.Response[diffv1.DiffContainerImagesResponse], error) {
	return c.diffClient.DiffContainerImages(ctx, req)
}

// ============================================================================
// Graph Service
// ============================================================================

// BuildGraph builds the dependency graph for a target.
func (c *Remote) BuildGraph(ctx context.Context, req *connect.Request[graphv1.BuildGraphRequest]) (*connect.Response[graphv1.BuildGraphResponse], error) {
	return c.graphClient.BuildGraph(ctx, req)
}

// WhyDependency finds paths explaining why a dependency is included.
func (c *Remote) WhyDependency(ctx context.Context, req *connect.Request[graphv1.WhyDependencyRequest]) (*connect.Response[graphv1.WhyDependencyResponse], error) {
	return c.graphClient.WhyDependency(ctx, req)
}

// QueryGraph queries the dependency graph with filters.
func (c *Remote) QueryGraph(ctx context.Context, req *connect.Request[graphv1.QueryGraphRequest]) (*connect.Response[graphv1.QueryGraphResponse], error) {
	return c.graphClient.QueryGraph(ctx, req)
}

// Mode returns the client's execution mode.
func (c *Remote) Mode() Mode {
	if c.isDaemon {
		return ModeLocalDaemon
	}
	return ModeRemote
}

// Close releases any resources held by the client.
func (c *Remote) Close() error {
	// Close idle connections
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

// connectStream wraps a ConnectRPC server stream to implement Stream[T].
// This is a generic adapter that works with any proto message type.
type connectStream[T any] struct {
	stream *connect.ServerStreamForClient[T]
}

// Receive returns the next message from the stream.
// Returns io.EOF when the stream is complete.
func (s *connectStream[T]) Receive() (*T, error) {
	if !s.stream.Receive() {
		if err := s.stream.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	return s.stream.Msg(), nil
}

// Close closes the stream and releases resources.
func (s *connectStream[T]) Close() error {
	return s.stream.Close()
}
