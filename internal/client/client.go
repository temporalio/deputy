package client

import (
	"context"

	"connectrpc.com/connect"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	remediationv1 "github.com/picatz/deputy/gen/deputy/remediation/v1"
	sbomv1 "github.com/picatz/deputy/gen/deputy/sbom/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	secretsv1 "github.com/picatz/deputy/gen/deputy/secrets/v1"
	"github.com/picatz/deputy/internal/scan"
)

// Client is the Deputy API client interface.
//
// All methods accept proto request types and return proto response types,
// enabling transparent switching between in-process and RPC execution modes.
type Client interface {
	// --- Vulnerability Scanning (ScanService) ---
	// Finds CVEs, advisories, and known vulnerabilities in dependencies.

	// Scan performs a vulnerability scan on a target to find CVEs in dependencies.
	Scan(ctx context.Context, req *connect.Request[scanv1.ScanRequest]) (*connect.Response[scanv1.ScanResponse], error)

	// StreamScan performs a vulnerability scan with streaming progress updates.
	StreamScan(ctx context.Context, req *connect.Request[scanv1.StreamScanRequest]) (Stream[scanv1.ScanProgress], error)

	// --- Package Enumeration (ListService) ---

	// ListPackages lists packages in a target.
	ListPackages(ctx context.Context, req *connect.Request[listv1.ListPackagesRequest]) (*connect.Response[listv1.ListPackagesResponse], error)

	// ListEcosystems lists supported package ecosystems.
	ListEcosystems(ctx context.Context, req *connect.Request[listv1.ListEcosystemsRequest]) (*connect.Response[listv1.ListEcosystemsResponse], error)

	// --- SBOM Service ---

	// GenerateSBOM generates a Software Bill of Materials.
	GenerateSBOM(ctx context.Context, req *connect.Request[sbomv1.GenerateRequest]) (*connect.Response[sbomv1.GenerateResponse], error)

	// DiffSBOM computes differences between two SBOMs.
	DiffSBOM(ctx context.Context, req *connect.Request[sbomv1.DiffRequest]) (*connect.Response[sbomv1.DiffResponse], error)

	// --- Remediation Service ---

	// GeneratePlan creates a remediation plan from scan results.
	// This is a read-only operation that proposes fixes without applying them.
	GeneratePlan(ctx context.Context, req *connect.Request[remediationv1.GeneratePlanRequest]) (*connect.Response[remediationv1.GeneratePlanResponse], error)

	// ExecutePlan applies a previously generated remediation plan.
	// Returns streaming progress updates during execution.
	ExecutePlan(ctx context.Context, req *connect.Request[remediationv1.ExecutePlanRequest]) (Stream[remediationv1.ExecutionEvent], error)

	// ExecuteWithAgent uses an AI agent to generate and apply fixes interactively.
	// Returns streaming events for real-time feedback.
	ExecuteWithAgent(ctx context.Context, req *connect.Request[remediationv1.ExecuteWithAgentRequest]) (Stream[remediationv1.AgentEvent], error)

	// ResumeAgent resumes a previous agent execution session.
	ResumeAgent(ctx context.Context, req *connect.Request[remediationv1.ResumeAgentRequest]) (Stream[remediationv1.AgentEvent], error)

	// ListAgents returns available AI agents for remediation.
	ListAgents(ctx context.Context, req *connect.Request[remediationv1.ListAgentsRequest]) (*connect.Response[remediationv1.ListAgentsResponse], error)

	// ApproveStep approves or denies a pending remediation step.
	ApproveStep(ctx context.Context, req *connect.Request[remediationv1.ApproveStepRequest]) (*connect.Response[remediationv1.ApproveStepResponse], error)

	// --- Secret Detection (SecretsService) ---
	// Finds leaked credentials, API keys, and other sensitive data.

	// ScanSecrets performs secret detection on a target to find leaked credentials.
	ScanSecrets(ctx context.Context, req *connect.Request[secretsv1.ScanRequest]) (*connect.Response[secretsv1.ScanResponse], error)

	// StreamScanSecrets performs secret detection with streaming progress updates.
	StreamScanSecrets(ctx context.Context, req *connect.Request[secretsv1.StreamScanRequest]) (Stream[secretsv1.ScanProgress], error)

	// ScanSecretsHistory scans git history for secrets that may have been committed.
	ScanSecretsHistory(ctx context.Context, req *connect.Request[secretsv1.ScanHistoryRequest]) (*connect.Response[secretsv1.ScanHistoryResponse], error)

	// ScanSecretsDiff scans changes between two git refs for newly introduced secrets.
	ScanSecretsDiff(ctx context.Context, req *connect.Request[secretsv1.ScanDiffRequest]) (*connect.Response[secretsv1.ScanDiffResponse], error)

	// VerifySecrets attempts to validate if detected secrets are still active.
	VerifySecrets(ctx context.Context, req *connect.Request[secretsv1.VerifyRequest]) (*connect.Response[secretsv1.VerifyResponse], error)

	// ListDetectors returns available secret detection patterns.
	ListDetectors(ctx context.Context, req *connect.Request[secretsv1.ListDetectorsRequest]) (*connect.Response[secretsv1.ListDetectorsResponse], error)

	// --- Client Lifecycle ---

	// Mode returns the client's execution mode.
	Mode() Mode

	// Close releases any resources held by the client.
	Close() error
}

// Stream is a generic streaming response interface.
// It provides a unified abstraction over ConnectRPC server streams,
// enabling transparent switching between in-process and RPC execution modes.
//
// Usage:
//
//	stream, err := client.StreamScan(ctx, req)
//	if err != nil { return err }
//	defer stream.Close()
//	for {
//	    msg, err := stream.Receive()
//	    if err == io.EOF { break }
//	    if err != nil { return err }
//	    // process msg
//	}
type Stream[T any] interface {
	// Receive returns the next message from the stream.
	// Returns io.EOF when the stream is complete.
	Receive() (*T, error)

	// Close closes the stream and releases resources.
	Close() error
}

// Mode indicates how the client connects to Deputy services.
type Mode int

const (
	// ModeInProcess uses direct function calls (default, zero overhead).
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

// Options configures client creation.
//
// Zero value enables automatic mode detection, which is the recommended default:
//
//	client, err := client.New(ctx, client.Options{})
//
// For explicit mode selection, set Mode and ForceMode:
//
//	client, err := client.New(ctx, client.Options{
//	    Mode:          client.ModeRemote,
//	    ForceMode:     true,
//	    ServerAddress: "https://deputy.example.com:8090",
//	})
type Options struct {
	// Mode overrides automatic mode detection.
	// If zero, mode is auto-detected based on environment.
	Mode Mode

	// ForceMode disables auto-detection and uses Mode as-is.
	// When false (default), Mode is treated as a hint that may be
	// overridden by environment detection.
	ForceMode bool

	// ServerAddress is the remote server address (for ModeRemote).
	// Example: "https://deputy.example.com:8090"
	// Can also be set via DEPUTY_SERVER environment variable.
	ServerAddress string

	// DaemonSocket is the Unix socket path (for ModeLocalDaemon).
	// Example: "/tmp/deputy-user/daemon.sock"
	// If empty, uses XDG_RUNTIME_DIR or system temp directory.
	DaemonSocket string

	// Scanner is the scan service for in-process mode.
	// If nil, a default scan.Service is created.
	Scanner scan.Scanner
}
