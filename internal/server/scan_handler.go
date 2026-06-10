package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	"github.com/temporalio/deputy/gen/deputy/scan/v1/scanv1connect"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/logs"
	"github.com/temporalio/deputy/internal/otel"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/scanning"
	"github.com/temporalio/deputy/internal/targets"
	"github.com/temporalio/deputy/internal/vulnerability/id/cve"
	"github.com/temporalio/deputy/internal/vulnerability/intel"
)

// ScanHandler implements the ScanService ConnectRPC service.
type ScanHandler struct {
	localMode    bool // Skip remote target validation for in-process usage
	targetPolicy *targets.RemoteTargetPolicy
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

// WithScanTargetPolicy sets the remote target policy for server mode validation.
func WithScanTargetPolicy(policy *targets.RemoteTargetPolicy) ScanHandlerOption {
	return func(h *ScanHandler) {
		h.targetPolicy = policy
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
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	target := req.Msg.Target
	if target == "" {
		err := fmt.Errorf("target is required")
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// Add business attributes to the otelconnect span
	span.SetAttributes(otel.AttrTargetPath.String(target))

	// Security: Validate target before processing (skip in local mode)
	if !h.localMode {
		if err := h.validateTarget(target); err != nil {
			otel.SetSpanError(span, err)
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	logs.Info(ctx, "received scan request", "target", target)

	// Build scanning options from proto
	opts := scanning.Options{VerifyFixes: true}
	if req.Msg.Options != nil {
		opts.Ecosystems = req.Msg.Options.Ecosystems
		opts.Platform = req.Msg.Options.Platform
		opts.DetectBaseImage = req.Msg.Options.DetectBaseImage
		opts.ExcludePaths = req.Msg.Options.GetExcludePaths()
		opts.VerifyFixes = !req.Msg.Options.DisableFixVerification
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
		otel.SetSpanError(span, err)
		logs.Error(ctx, "scan failed", "target", target, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("scan failed: %w", err))
	}

	// Ensure cleanup happens
	if execution != nil {
		defer execution.Close()
	}

	// Convert result to proto
	response := internalproto.ScanningResultToProto(&execution.Result)

	// Enrich vulnerabilities with EPSS/KEV data if requested
	if req.Msg.Options != nil && req.Msg.Options.EnrichOptions != nil && req.Msg.Options.EnrichOptions.Enabled {
		enrichFindings(ctx, response.Findings, req.Msg.Options.EnrichOptions)
	}

	// Record scan results on the span
	otel.RecordScanResults(span,
		int(response.PackagesScanned),
		len(response.Findings),
		countBySeverity(response.Findings, vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL),
		countBySeverity(response.Findings, vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH),
		countBySeverity(response.Findings, vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM),
		countBySeverity(response.Findings, vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW),
	)

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

	case targets.KindVMImage:
		return scanning.ScanVMImage(ctx, target, nil, opts)

	case targets.KindGit:
		return scanning.ScanRepository(ctx, target, ref, refProvided, opts)

	default:
		// Default: try repository scan (handles remote repos)
		return scanning.ScanRepository(ctx, target, ref, refProvided, opts)
	}
}

// validateTarget performs security validation on the target string for remote server mode.
func (h *ScanHandler) validateTarget(target string) error {
	return targets.ValidateRemoteTargetWithPolicy(target, h.targetPolicy)
}

// StreamScan performs a vulnerability scan with streaming progress updates.
func (h *ScanHandler) StreamScan(
	ctx context.Context,
	req *connect.Request[scanv1.StreamScanRequest],
	stream *connect.ServerStream[scanv1.ScanProgress],
) error {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return connect.NewError(connect.CodeInvalidArgument, err)
	}

	target := req.Msg.Target
	if target == "" {
		err := fmt.Errorf("target is required")
		otel.SetSpanError(span, err)
		return connect.NewError(connect.CodeInvalidArgument, err)
	}

	// Add business attributes to the otelconnect span
	span.SetAttributes(otel.AttrTargetPath.String(target))

	// Security: Validate target before processing (skip in local mode)
	if !h.localMode {
		if err := h.validateTarget(target); err != nil {
			otel.SetSpanError(span, err)
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
	opts := scanning.Options{VerifyFixes: true}
	if req.Msg.Options != nil {
		opts.Ecosystems = req.Msg.Options.Ecosystems
		opts.Platform = req.Msg.Options.Platform
		opts.DetectBaseImage = req.Msg.Options.DetectBaseImage
		opts.ExcludePaths = req.Msg.Options.GetExcludePaths()
		opts.VerifyFixes = !req.Msg.Options.DisableFixVerification
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
		otel.SetSpanError(span, err)
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

	// Enrich vulnerabilities with EPSS/KEV data if requested
	if req.Msg.Options != nil && req.Msg.Options.EnrichOptions != nil && req.Msg.Options.EnrichOptions.Enabled {
		enrichFindings(ctx, response.Findings, req.Msg.Options.EnrichOptions)
	}

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

	// Record scan results on the span
	otel.RecordScanResults(span,
		int(response.PackagesScanned),
		len(response.Findings),
		countBySeverity(response.Findings, vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL),
		countBySeverity(response.Findings, vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH),
		countBySeverity(response.Findings, vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM),
		countBySeverity(response.Findings, vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW),
	)

	logs.Info(ctx, "streaming scan completed",
		"target", target,
		"packages_scanned", response.PackagesScanned,
		"findings", len(response.Findings),
	)

	return nil
}

// countBySeverity counts findings with the given severity level.
func countBySeverity(findings []*vulnerabilityv1.Finding, level vulnerabilityv1.SeverityLevel) int {
	count := 0
	for _, f := range findings {
		if f.GetAdvisory().GetSeverity().GetLevel() == level {
			count++
		}
	}
	return count
}

// enrichFindings enriches vulnerability findings with EPSS and KEV data.
func enrichFindings(ctx context.Context, findings []*vulnerabilityv1.Finding, opts *scanv1.EnrichOptions) {
	if len(findings) == 0 {
		return
	}

	// Collect CVE IDs for batch lookup
	cveIDs := make([]string, 0, len(findings))
	cveToIndices := make(map[string][]int) // CVE -> finding indices

	for i, f := range findings {
		cveID := extractCVE(f)
		if cveID != "" {
			if _, seen := cveToIndices[cveID]; !seen {
				cveIDs = append(cveIDs, cveID)
			}
			cveToIndices[cveID] = append(cveToIndices[cveID], i)
		}
	}

	if len(cveIDs) == 0 {
		return
	}

	// Batch enrichment
	enricher := intel.NewEnricher(&intel.EnricherConfig{DiskCache: true})
	results := enricher.EnrichBatch(ctx, cveIDs)

	// Apply enrichment results to findings
	for cveID, indices := range cveToIndices {
		enrichment, ok := results[cveID]
		if !ok {
			continue
		}

		for _, idx := range indices {
			f := findings[idx]

			// Apply EPSS data if requested
			if opts.IncludeEpss || opts.Enabled {
				if enrichment.EPSS != nil {
					f.Epss = enrichment.EPSS
				}
				if enrichment.EPSSPercentile != nil {
					f.EpssPercentile = enrichment.EPSSPercentile
				}
			}

			// Apply KEV data if requested
			if opts.IncludeKev || opts.Enabled {
				if enrichment.InKEV != nil {
					f.InKev = enrichment.InKEV
				}
			}
		}
	}
}

// extractCVE extracts CVE ID from a finding.
func extractCVE(f *vulnerabilityv1.Finding) string {
	if f == nil || f.Advisory == nil {
		return ""
	}

	// Check the CVE field first
	if f.Advisory.Cve != "" && cve.IsValid(f.Advisory.Cve) {
		return f.Advisory.Cve
	}

	// Check the primary ID
	if cve.IsValid(f.AdvisoryId) {
		return f.AdvisoryId
	}

	// Check aliases
	for _, alias := range f.Advisory.Aliases {
		if cve.IsValid(alias) {
			return alias
		}
	}

	return ""
}
