package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	"github.com/picatz/deputy/gen/deputy/scan/v1/scanv1connect"
	"github.com/picatz/deputy/internal/logs"
	internalproto "github.com/picatz/deputy/internal/proto"
	"github.com/picatz/deputy/internal/scanning"
	"github.com/picatz/deputy/internal/targets"
)

// ScanHandler implements the ScanService ConnectRPC service.
type ScanHandler struct {
	localMode bool // Skip remote target validation for in-process usage
}

// Ensure ScanHandler implements the ScanServiceHandler interface.
var _ scanv1connect.ScanServiceHandler = (*ScanHandler)(nil)

// ScanHandlerOption configures a ScanHandler.
type ScanHandlerOption func(*ScanHandler)

// WithLocalMode enables local mode which skips remote target validation.
// Use this for in-process clients that need to access local filesystems.
func WithLocalMode() ScanHandlerOption {
	return func(h *ScanHandler) {
		h.localMode = true
	}
}

// NewScanHandler creates a new ScanHandler.
func NewScanHandler(opts ...ScanHandlerOption) *ScanHandler {
	h := &ScanHandler{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// Scan performs a vulnerability scan on a target.
func (h *ScanHandler) Scan(
	ctx context.Context,
	req *connect.Request[scanv1.ScanRequest],
) (*connect.Response[scanv1.ScanResponse], error) {
	target := req.Msg.Target
	if target == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target is required"))
	}

	// Security: Validate target before processing (skip in local mode)
	if !h.localMode {
		if err := validateTarget(target); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	logs.Info(ctx, "received scan request", "target", target)

	// Build scanning options from proto
	opts := scanning.Options{}
	if req.Msg.Options != nil {
		opts.Ecosystems = req.Msg.Options.Ecosystems
		opts.Platform = req.Msg.Options.Platform
	}

	// Extract ref from options if provided
	ref := ""
	refProvided := false
	if req.Msg.Options != nil && req.Msg.Options.Ref != "" {
		ref = req.Msg.Options.Ref
		refProvided = true
	}

	// Detect target kind using explicit hint or auto-detection
	kind := targets.KindUnspecified
	if req.Msg.Options != nil && req.Msg.Options.TargetHint != nil {
		kind = targets.Kind(req.Msg.Options.TargetHint.Kind)
	}
	if kind == targets.KindUnspecified {
		kind = targets.DetectKind(target)
	}

	// Get image transport hint if provided
	imageTransport := ""
	if req.Msg.Options != nil && req.Msg.Options.TargetHint != nil {
		imageTransport = req.Msg.Options.TargetHint.ImageTransport
	}

	// Route to appropriate scanner based on target type
	execution, err := h.routeScan(ctx, target, ref, refProvided, kind, imageTransport, opts)
	if err != nil {
		logs.Error(ctx, "scan failed", "target", target, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("scan failed: %w", err))
	}

	// Ensure cleanup happens
	if execution != nil {
		defer execution.Close()
	}

	// Convert result to proto
	response := internalproto.ScanningResultToProto(&execution.Result)

	logs.Info(ctx, "scan completed",
		"target", target,
		"packages_scanned", response.PackagesScanned,
		"findings", len(response.Findings),
	)

	return connect.NewResponse(response), nil
}

// routeScan routes to the appropriate scanner method based on target type.
//
// Security considerations for remote server mode:
//   - Local filesystem paths are rejected by validateTarget before this is called
//   - Only remote-accessible targets are allowed: git URLs, container registries, PURLs
//   - stdin SBOM ("-") is rejected; clients must upload SBOM bytes instead
func (h *ScanHandler) routeScan(ctx context.Context, target, ref string, refProvided bool, kind targets.Kind, imageTransport string, opts scanning.Options) (*scanning.Execution, error) {
	// For server mode, we only support remote-accessible targets.
	// Local-only types (Dir, SBOM files, Dockerfiles) are rejected by validateTarget
	// or fall through to repository scan.
	switch kind {
	case targets.KindPURL:
		return scanning.ScanPURL(ctx, target, opts)

	case targets.KindContainerImage:
		targetOpts := map[string]string{}
		if opts.Platform != "" {
			targetOpts["platform"] = opts.Platform
		}
		if imageTransport != "" {
			targetOpts["transport"] = imageTransport
		}
		return scanning.ScanContainerImage(ctx, target, targetOpts, opts)

	case targets.KindGit:
		return scanning.ScanRepository(ctx, target, ref, refProvided, opts)

	default:
		// Default: try repository scan (handles remote repos)
		return scanning.ScanRepository(ctx, target, ref, refProvided, opts)
	}
}

// validateTarget performs security validation on the target string for remote server mode.
// Uses the shared targets.ValidateRemoteTarget function.
func validateTarget(target string) error {
	return targets.ValidateRemoteTarget(target)
}

// StreamScan performs a vulnerability scan with streaming progress updates.
func (h *ScanHandler) StreamScan(
	ctx context.Context,
	req *connect.Request[scanv1.StreamScanRequest],
	stream *connect.ServerStream[scanv1.ScanProgress],
) error {
	target := req.Msg.Target
	if target == "" {
		return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target is required"))
	}

	// Security: Validate target before processing (skip in local mode)
	if !h.localMode {
		if err := validateTarget(target); err != nil {
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	logs.Info(ctx, "received streaming scan request", "target", target)

	// Send initializing phase
	if err := stream.Send(&scanv1.ScanProgress{
		Phase:   scanv1.ScanPhase_SCAN_PHASE_INITIALIZING,
		Message: "Initializing scan...",
	}); err != nil {
		return err
	}

	// Build scanning options from proto
	opts := scanning.Options{}
	if req.Msg.Options != nil {
		opts.Ecosystems = req.Msg.Options.Ecosystems
		opts.Platform = req.Msg.Options.Platform
	}

	// Send resolving target phase
	if err := stream.Send(&scanv1.ScanProgress{
		Phase:   scanv1.ScanPhase_SCAN_PHASE_RESOLVING_TARGET,
		Message: fmt.Sprintf("Resolving target: %s", target),
	}); err != nil {
		return err
	}

	// Extract ref from options if provided
	ref := ""
	refProvided := false
	if req.Msg.Options != nil && req.Msg.Options.Ref != "" {
		ref = req.Msg.Options.Ref
		refProvided = true
	}

	// Detect target kind using explicit hint or auto-detection
	kind := targets.KindUnspecified
	if req.Msg.Options != nil && req.Msg.Options.TargetHint != nil {
		kind = targets.Kind(req.Msg.Options.TargetHint.Kind)
	}
	if kind == targets.KindUnspecified {
		kind = targets.DetectKind(target)
	}

	// Get image transport hint if provided
	imageTransport := ""
	if req.Msg.Options != nil && req.Msg.Options.TargetHint != nil {
		imageTransport = req.Msg.Options.TargetHint.ImageTransport
	}

	// Send extracting inventory phase
	if err := stream.Send(&scanv1.ScanProgress{
		Phase:   scanv1.ScanPhase_SCAN_PHASE_EXTRACTING_INVENTORY,
		Message: "Extracting package inventory...",
	}); err != nil {
		return err
	}

	// Perform the scan using unified routing
	execution, err := h.routeScan(ctx, target, ref, refProvided, kind, imageTransport, opts)
	if err != nil {
		// Send failed phase
		_ = stream.Send(&scanv1.ScanProgress{
			Phase:   scanv1.ScanPhase_SCAN_PHASE_FAILED,
			Message: fmt.Sprintf("Scan failed: %v", err),
			Error:   err.Error(),
		})
		return connect.NewError(connect.CodeInternal, fmt.Errorf("scan failed: %w", err))
	}

	// Ensure cleanup happens
	if execution != nil {
		defer execution.Close()
	}

	// Convert result to proto
	response := internalproto.ScanningResultToProto(&execution.Result)

	// Send complete phase with result
	if err := stream.Send(&scanv1.ScanProgress{
		Phase:                scanv1.ScanPhase_SCAN_PHASE_COMPLETE,
		Message:              "Scan completed",
		PackagesFound:        response.PackagesScanned,
		VulnerabilitiesFound: int32(len(response.Findings)),
		Result:               response,
	}); err != nil {
		return err
	}

	logs.Info(ctx, "streaming scan completed",
		"target", target,
		"packages_scanned", response.PackagesScanned,
		"findings", len(response.Findings),
	)

	return nil
}
