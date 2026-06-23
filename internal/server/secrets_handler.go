package server

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	secretsv1 "github.com/temporalio/deputy/gen/deputy/secrets/v1"
	"github.com/temporalio/deputy/gen/deputy/secrets/v1/secretsv1connect"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	"github.com/temporalio/deputy/internal/gitutil"
	"github.com/temporalio/deputy/internal/globmatch"
	"github.com/temporalio/deputy/internal/logs"
	"github.com/temporalio/deputy/internal/otel"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/secrets"
	"github.com/temporalio/deputy/internal/targets"

	// Register target providers for remote Git, containers, etc.
	_ "github.com/temporalio/deputy/internal/targets/providers"
)

// SecretsHandler implements the SecretsService ConnectRPC service.
type SecretsHandler struct {
	secretsv1connect.UnimplementedSecretsServiceHandler

	engine          *secrets.Engine
	customDetectors []secrets.PatternDetector
	localMode       bool // Skip remote target validation for in-process usage
	targetPolicy    *targets.RemoteTargetPolicy
}

// SecretsHandlerOption configures a SecretsHandler.
type SecretsHandlerOption func(*SecretsHandler)

// WithSecretsLocalMode enables local mode which skips remote target validation.
// Use this for in-process clients that need to access local filesystems.
func WithSecretsLocalMode() SecretsHandlerOption {
	return func(h *SecretsHandler) {
		h.localMode = true
	}
}

// WithSecretsTargetPolicy sets the remote target policy for server mode validation.
func WithSecretsTargetPolicy(policy *targets.RemoteTargetPolicy) SecretsHandlerOption {
	return func(h *SecretsHandler) {
		h.targetPolicy = policy
	}
}

// Ensure SecretsHandler implements the SecretsServiceHandler interface.
var _ secretsv1connect.SecretsServiceHandler = (*SecretsHandler)(nil)

// NewSecretsHandler creates a new SecretsHandler with default configuration.
func NewSecretsHandler(opts ...SecretsHandlerOption) (*SecretsHandler, error) {
	engine, err := secrets.NewEngine()
	if err != nil {
		return nil, fmt.Errorf("failed to create secrets engine: %w", err)
	}
	h := &SecretsHandler{
		engine:          engine,
		customDetectors: make([]secrets.PatternDetector, 0),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h, nil
}

// NewSecretsHandlerWithConfig creates a new SecretsHandler with custom configuration.
func NewSecretsHandlerWithConfig(config secrets.EngineConfig) (*SecretsHandler, error) {
	engine, err := secrets.NewEngineWithConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create secrets engine: %w", err)
	}
	return &SecretsHandler{
		engine:          engine,
		customDetectors: config.CustomPatterns,
	}, nil
}

// Scan performs secret detection on a target.
func (h *SecretsHandler) Scan(
	ctx context.Context,
	req *connect.Request[secretsv1.ScanRequest],
) (*connect.Response[secretsv1.ScanResponse], error) {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	target := req.Msg.Target
	if target == "" {
		target = "."
	}

	// Add business attributes to the otelconnect span
	span.SetAttributes(otel.AttrTargetPath.String(target))

	// Security: Validate target before processing (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTargetWithPolicy(target, h.targetPolicy); err != nil {
			otel.SetSpanError(span, err)
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	logs.Info(ctx, "received secrets scan request", "target", target)

	// Build scan options from request
	opts := h.buildScanOptions(req.Msg.Options)

	// Detect target type and scan accordingly
	findings, warnings, err := h.scanTarget(ctx, target, opts)
	if err != nil {
		otel.SetSpanError(span, err)
		logs.Error(ctx, "secrets scan failed", "target", target, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("secrets scan failed: %w", err))
	}

	// Build response
	response := &secretsv1.ScanResponse{
		Target: &targetv1.Target{
			Kind:        targets.DetectKind(target),
			DisplayPath: target,
		},
		GeneratedAt: timestamppb.New(time.Now()),
		Findings:    internalproto.SecretsFindingsToProto(findings),
		Stats:       internalproto.SecretsStatsToProto(findings),
		Warnings:    warnings,
	}

	logs.Info(ctx, "secrets scan completed",
		"target", target,
		"findings", len(findings),
	)

	return connect.NewResponse(response), nil
}

// StreamScan performs secret detection with streaming progress updates.
func (h *SecretsHandler) StreamScan(
	ctx context.Context,
	req *connect.Request[secretsv1.StreamScanRequest],
	stream *connect.ServerStream[secretsv1.ScanProgress],
) error {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return connect.NewError(connect.CodeInvalidArgument, err)
	}

	target := req.Msg.Target
	if target == "" {
		target = "."
	}

	// Add business attributes to the otelconnect span
	span.SetAttributes(otel.AttrTargetPath.String(target))

	// Security: Validate target before processing (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTargetWithPolicy(target, h.targetPolicy); err != nil {
			otel.SetSpanError(span, err)
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	logs.Info(ctx, "received streaming secrets scan request", "target", target)

	// Send initializing phase
	if err := stream.Send(&secretsv1.ScanProgress{
		Phase:   secretsv1.ScanPhase_SCAN_PHASE_INITIALIZING,
		Message: "Initializing secrets scan...",
	}); err != nil {
		return err
	}

	// Build scan options from request
	opts := h.buildScanOptions(req.Msg.Options)

	// Send resolving target phase
	if err := stream.Send(&secretsv1.ScanProgress{
		Phase:   secretsv1.ScanPhase_SCAN_PHASE_RESOLVING_TARGET,
		Message: fmt.Sprintf("Resolving target: %s", target),
	}); err != nil {
		return err
	}

	// Send extracting files phase
	if err := stream.Send(&secretsv1.ScanProgress{
		Phase:   secretsv1.ScanPhase_SCAN_PHASE_EXTRACTING_FILES,
		Message: "Extracting files to scan...",
	}); err != nil {
		return err
	}

	// Perform the scan
	findings, warnings, err := h.scanTarget(ctx, target, opts)
	if err != nil {
		otel.SetSpanError(span, err)
		_ = stream.Send(&secretsv1.ScanProgress{
			Phase:   secretsv1.ScanPhase_SCAN_PHASE_FAILED,
			Message: fmt.Sprintf("Secrets scan failed: %v", err),
			Error:   err.Error(),
		})
		return connect.NewError(connect.CodeInternal, fmt.Errorf("secrets scan failed: %w", err))
	}

	// Build response
	response := &secretsv1.ScanResponse{
		Target: &targetv1.Target{
			Kind:        targets.DetectKind(target),
			DisplayPath: target,
		},
		GeneratedAt: timestamppb.New(time.Now()),
		Findings:    internalproto.SecretsFindingsToProto(findings),
		Stats:       internalproto.SecretsStatsToProto(findings),
		Warnings:    warnings,
	}

	// Send complete phase with result
	if err := stream.Send(&secretsv1.ScanProgress{
		Phase:        secretsv1.ScanPhase_SCAN_PHASE_COMPLETE,
		Message:      "Secrets scan completed",
		SecretsFound: int32(len(findings)),
		Result:       response,
	}); err != nil {
		return err
	}

	logs.Info(ctx, "streaming secrets scan completed",
		"target", target,
		"findings", len(findings),
	)

	return nil
}

// ScanHistory scans git history for secrets.
func (h *SecretsHandler) ScanHistory(
	ctx context.Context,
	req *connect.Request[secretsv1.ScanHistoryRequest],
) (*connect.Response[secretsv1.ScanHistoryResponse], error) {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	target := req.Msg.Target
	if target == "" {
		target = "."
	}

	// Add business attributes to the otelconnect span
	span.SetAttributes(otel.AttrTargetPath.String(target))

	// Security: Validate target before processing (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTargetWithPolicy(target, h.targetPolicy); err != nil {
			otel.SetSpanError(span, err)
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	logs.Info(ctx, "received secrets history scan request", "target", target)

	// Use the existing git history scanning from internal/secrets
	historyFindings, err := secrets.ScanGitHistory(ctx, target, secrets.GitHistoryOptions{
		MaxCommits:     int(req.Msg.MaxCommits),
		Since:          req.Msg.Since,
		Until:          req.Msg.Until,
		Branch:         req.Msg.Branch,
		IncludeRemoved: req.Msg.IncludeRemoved,
	})
	if err != nil {
		otel.SetSpanError(span, err)
		logs.Error(ctx, "secrets history scan failed", "target", target, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("secrets history scan failed: %w", err))
	}

	// Convert findings
	var findings []secrets.Finding
	for _, hf := range historyFindings {
		findings = append(findings, hf.Finding)
	}

	response := &secretsv1.ScanHistoryResponse{
		Target: &targetv1.Target{
			Kind:        targetv1.TargetKind_TARGET_KIND_GIT,
			DisplayPath: target,
		},
		GeneratedAt:    timestamppb.New(time.Now()),
		Findings:       h.historyFindingsToProto(historyFindings),
		CommitsScanned: int32(len(historyFindings)), // Approximate
		Stats:          internalproto.SecretsStatsToProto(findings),
	}

	return connect.NewResponse(response), nil
}

// ScanDiff scans changes between two git refs for secrets.
func (h *SecretsHandler) ScanDiff(
	ctx context.Context,
	req *connect.Request[secretsv1.ScanDiffRequest],
) (*connect.Response[secretsv1.ScanDiffResponse], error) {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	target := req.Msg.Target
	if target == "" {
		target = "."
	}

	baseRef := req.Msg.BaseRef
	targetRef := req.Msg.TargetRef

	// Add business attributes to the otelconnect span
	span.SetAttributes(
		otel.AttrTargetPath.String(target),
		otel.AttrMCPBaseRef.String(baseRef),
		otel.AttrMCPTargetRef.String(targetRef),
	)

	// Security: Validate target before processing (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTargetWithPolicy(target, h.targetPolicy); err != nil {
			otel.SetSpanError(span, err)
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	logs.Info(ctx, "received secrets diff scan request",
		"target", target,
		"base_ref", baseRef,
		"target_ref", targetRef,
	)

	// Use the existing diff scanning from internal/secrets
	diffResult, err := secrets.ScanGitDiff(ctx, target, baseRef, targetRef)
	if err != nil {
		otel.SetSpanError(span, err)
		logs.Error(ctx, "secrets diff scan failed", "target", target, "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("secrets diff scan failed: %w", err))
	}

	// Record results on span
	otel.AddSpanEvent(span, "secrets.diff_complete",
		otel.AttrMCPChangeCount.Int(len(diffResult.Added)+len(diffResult.Removed)),
	)

	response := &secretsv1.ScanDiffResponse{
		Target: &targetv1.Target{
			Kind:        targetv1.TargetKind_TARGET_KIND_GIT,
			DisplayPath: target,
		},
		GeneratedAt:     timestamppb.New(time.Now()),
		BaseRef:         baseRef,
		TargetRef:       targetRef,
		AddedFindings:   internalproto.SecretsFindingsToProto(diffResult.Added),
		RemovedFindings: internalproto.SecretsFindingsToProto(diffResult.Removed),
		Stats:           internalproto.SecretsStatsToProto(diffResult.Added),
	}

	return connect.NewResponse(response), nil
}

// Verify attempts to validate detected secrets.
func (h *SecretsHandler) Verify(
	ctx context.Context,
	req *connect.Request[secretsv1.VerifyRequest],
) (*connect.Response[secretsv1.VerifyResponse], error) {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	findings := internalproto.SecretsFindingsFromProto(req.Msg.Findings)

	logs.Info(ctx, "received secrets verify request", "findings_count", len(findings))

	// Verify findings
	verifiedFindings, err := secrets.VerifyFindings(ctx, findings, secrets.VerifyOptions{
		RateLimit: int(req.Msg.RateLimit),
		Timeout:   time.Duration(req.Msg.TimeoutSeconds) * time.Second,
	})
	if err != nil {
		otel.SetSpanError(span, err)
		logs.Error(ctx, "secrets verify failed", "error", err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("secrets verify failed: %w", err))
	}

	// Count results
	var verifiedCount, failedCount, skippedCount int32
	for _, f := range verifiedFindings {
		if f.Validated {
			verifiedCount++
		} else {
			// Check if it was skipped or actually failed
			skippedCount++ // Simplified; would need more detailed tracking
		}
	}

	// Record verification results on span
	otel.AddSpanEvent(span, "secrets.verify_complete",
		otel.AttrMCPVulnerabilityCount.Int(len(findings)),
	)

	response := &secretsv1.VerifyResponse{
		Results:       internalproto.SecretsFindingsToProto(verifiedFindings),
		VerifiedCount: verifiedCount,
		FailedCount:   failedCount,
		SkippedCount:  skippedCount,
	}

	return connect.NewResponse(response), nil
}

// ListDetectors returns available secret detectors.
func (h *SecretsHandler) ListDetectors(
	ctx context.Context,
	req *connect.Request[secretsv1.ListDetectorsRequest],
) (*connect.Response[secretsv1.ListDetectorsResponse], error) {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	detectors := h.getDetectorInfos(req.Msg.IncludeDisabled)

	// Filter by sources if specified
	if len(req.Msg.Sources) > 0 {
		sourceSet := make(map[secretsv1.DetectorSource]bool)
		for _, s := range req.Msg.Sources {
			sourceSet[s] = true
		}
		var filtered []*secretsv1.DetectorInfo
		for _, d := range detectors {
			if sourceSet[d.Source] {
				filtered = append(filtered, d)
			}
		}
		detectors = filtered
	}

	return connect.NewResponse(&secretsv1.ListDetectorsResponse{
		Detectors: detectors,
	}), nil
}

// RegisterDetector registers a custom detector (plugin support).
func (h *SecretsHandler) RegisterDetector(
	ctx context.Context,
	req *connect.Request[secretsv1.RegisterDetectorRequest],
) (*connect.Response[secretsv1.RegisterDetectorResponse], error) {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	info := req.Msg.Detector
	pattern := req.Msg.Pattern

	if info == nil {
		err := fmt.Errorf("detector info is required")
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if pattern == "" {
		err := fmt.Errorf("pattern is required for pattern-based detectors")
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// Compile the pattern
	re, err := regexp.Compile(pattern)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid regex pattern: %w", err))
	}

	// Create custom detector
	detector := secrets.PatternDetector{
		Type:        secrets.SecretType(info.Id),
		Pattern:     re,
		Description: info.Description,
		Confidence:  0.9, // Default confidence for custom patterns
	}

	// Add to custom detectors
	h.customDetectors = append(h.customDetectors, detector)

	// Return the registered detector info
	info.Source = secretsv1.DetectorSource_DETECTOR_SOURCE_CUSTOM
	info.Enabled = true

	logs.Info(ctx, "registered custom detector", "id", info.Id, "name", info.Name)

	return connect.NewResponse(&secretsv1.RegisterDetectorResponse{
		Detector: info,
	}), nil
}

// scanTarget scans a target for secrets based on its type.
func (h *SecretsHandler) scanTarget(ctx context.Context, target string, opts scanOptions) ([]secrets.Finding, []string, error) {
	kind := targets.DetectKind(target)

	switch kind {
	case targets.KindDir:
		return h.scanDirectory(ctx, target, opts)
	case targets.KindContainerImage:
		return h.scanContainerImage(ctx, target, opts)
	case targets.KindGit:
		return h.scanRepository(ctx, target, opts)
	default:
		// Check if target looks like a remote Git URL
		if gitutil.ToHTTPSGitURL(target) != "" || strings.HasPrefix(target, "git@") {
			return h.scanRepository(ctx, target, opts)
		}

		// Try as file or directory
		info, err := os.Stat(target)
		if err != nil {
			return nil, nil, fmt.Errorf("target not found: %w", err)
		}
		if info.IsDir() {
			return h.scanDirectory(ctx, target, opts)
		}
		return h.scanFile(ctx, target, opts)
	}
}

// scanDirectory scans a directory for secrets.
func (h *SecretsHandler) scanDirectory(ctx context.Context, dir string, opts scanOptions) ([]secrets.Finding, []string, error) {
	var findings []secrets.Finding
	var warnings []string

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	rootFS := root.FS()

	err = fs.WalkDir(rootFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			displayPath := filepath.Join(dir, filepath.FromSlash(path))
			warnings = append(warnings, fmt.Sprintf("error accessing %s: %v", displayPath, err))
			return nil
		}
		relPath := filepath.FromSlash(path)

		// Skip directories and common exclusions
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		// Check include/exclude patterns
		if !opts.matchesInclude(relPath) || opts.matchesExclude(relPath) {
			return nil
		}

		// Read and scan file
		content, err := fs.ReadFile(rootFS, path)
		if err != nil {
			displayPath := filepath.Join(dir, relPath)
			warnings = append(warnings, fmt.Sprintf("error reading %s: %v", displayPath, err))
			return nil
		}

		fileFindings, err := h.engine.ScanFile(ctx, relPath, content)
		if err != nil {
			displayPath := filepath.Join(dir, relPath)
			warnings = append(warnings, fmt.Sprintf("error scanning %s: %v", displayPath, err))
			return nil
		}

		// Filter by confidence
		for _, f := range fileFindings {
			if f.Confidence >= opts.minConfidence {
				findings = append(findings, f)
			}
		}

		return nil
	})

	return findings, warnings, err
}

// scanFile scans a single file for secrets.
func (h *SecretsHandler) scanFile(ctx context.Context, path string, opts scanOptions) ([]secrets.Finding, []string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading file: %w", err)
	}

	findings, err := h.engine.ScanFile(ctx, path, content)
	if err != nil {
		return nil, nil, fmt.Errorf("error scanning file: %w", err)
	}

	// Filter by confidence
	var filtered []secrets.Finding
	for _, f := range findings {
		if f.Confidence >= opts.minConfidence {
			filtered = append(filtered, f)
		}
	}

	return filtered, nil, nil
}

// scanContainerImage scans a container image for secrets.
func (h *SecretsHandler) scanContainerImage(ctx context.Context, ref string, opts scanOptions) ([]secrets.Finding, []string, error) {
	findings, warnings, err := secrets.ScanContainerImage(ctx, ref, secrets.ContainerScanOptions{
		Deep:     opts.deep,
		Platform: opts.platform,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error scanning container image: %w", err)
	}

	// Filter by confidence
	var filtered []secrets.Finding
	for _, f := range findings {
		if f.Confidence >= opts.minConfidence {
			filtered = append(filtered, f)
		}
	}

	return filtered, warnings, nil
}

// scanRepository scans a git repository for secrets.
// For remote Git URLs (e.g., github.com/owner/repo), this clones the repo first.
// For local repos, it scans directly.
func (h *SecretsHandler) scanRepository(ctx context.Context, target string, opts scanOptions) ([]secrets.Finding, []string, error) {
	// Check if target is a local path
	if info, err := os.Stat(target); err == nil && info.IsDir() {
		// Local directory - scan directly
		return h.scanDirectory(ctx, target, opts)
	}

	// Remote target - use targets provider system to materialize (clone)
	logs.Info(ctx, "materializing remote git target", "target", target)

	mat, err := targets.Open(ctx, target, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to materialize target %q: %w", target, err)
	}
	// Ensure cleanup of temporary clone
	if mat.Cleanup != nil {
		defer mat.Cleanup()
	}

	// Now scan the materialized path
	return h.scanDirectory(ctx, mat.Path, opts)
}

// scanOptions holds processed scan options.
type scanOptions struct {
	detectorIDs      []string
	secretTypes      []secretsv1.SecretType
	minConfidence    float64
	verify           bool
	includePatterns  []string
	excludePatterns  []string
	entropyEnabled   bool
	entropyThreshold float64
	deep             bool
	baselinePath     string
	platform         string
}

// buildScanOptions converts proto options to internal options.
func (h *SecretsHandler) buildScanOptions(opts *secretsv1.ScanOptions) scanOptions {
	if opts == nil {
		return scanOptions{minConfidence: 0.0}
	}

	return scanOptions{
		detectorIDs:      opts.DetectorIds,
		secretTypes:      opts.SecretTypes,
		minConfidence:    float64(opts.MinConfidence),
		verify:           opts.Verify,
		includePatterns:  opts.IncludePatterns,
		excludePatterns:  opts.ExcludePatterns,
		entropyEnabled:   opts.EntropyDetection,
		entropyThreshold: float64(opts.EntropyThreshold),
		deep:             opts.Deep,
		baselinePath:     opts.BaselinePath,
		platform:         opts.Platform,
	}
}

// matchesInclude checks if path matches include patterns (empty = all). The
// path is matched in full with globmatch's gitignore-flavored semantics (bare
// names match at any depth, "dir/**" matches the whole subtree), so
// path-qualified patterns now match instead of only the basename. Compiled per
// call; a malformed pattern is treated as no-match.
func (opts scanOptions) matchesInclude(path string) bool {
	if len(opts.includePatterns) == 0 {
		return true
	}
	m, err := globmatch.Compile(opts.includePatterns)
	if err != nil {
		return false
	}
	return m.MatchPath(path)
}

// matchesExclude checks if path matches exclude patterns. The path is matched in
// full with globmatch's gitignore-flavored semantics, so path-qualified patterns
// now match instead of only the basename. Compiled per call; a malformed pattern
// is treated as no-match.
func (opts scanOptions) matchesExclude(path string) bool {
	m, err := globmatch.Compile(opts.excludePatterns)
	if err != nil {
		return false
	}
	return m.MatchPath(path)
}

// shouldSkipDir returns true for directories that should be skipped.
func shouldSkipDir(name string) bool {
	skipDirs := map[string]bool{
		".git":         true,
		"node_modules": true,
		"vendor":       true,
		"__pycache__":  true,
		".venv":        true,
		"venv":         true,
		".idea":        true,
		".vscode":      true,
		"dist":         true,
		"build":        true,
		"target":       true,
		".terraform":   true,
	}
	return skipDirs[name]
}

// getDetectorInfos returns information about available detectors.
func (h *SecretsHandler) getDetectorInfos(includeDisabled bool) []*secretsv1.DetectorInfo {
	// Built-in pattern detectors
	builtinDetectors := []struct {
		id          string
		name        string
		description string
		types       []secretsv1.SecretType
	}{
		{"aws", "AWS Credentials", "Detects AWS access keys and secret keys", []secretsv1.SecretType{secretsv1.SecretType_SECRET_TYPE_AWS_ACCESS_KEY, secretsv1.SecretType_SECRET_TYPE_AWS_SECRET_KEY}},
		{"github", "GitHub Tokens", "Detects GitHub personal access tokens", []secretsv1.SecretType{secretsv1.SecretType_SECRET_TYPE_GITHUB_TOKEN, secretsv1.SecretType_SECRET_TYPE_GITHUB_FINE_GRAINED_TOKEN}},
		{"gcp", "GCP Credentials", "Detects GCP API keys and service account keys", []secretsv1.SecretType{secretsv1.SecretType_SECRET_TYPE_GCP_API_KEY, secretsv1.SecretType_SECRET_TYPE_GCP_SERVICE_ACCOUNT_KEY}},
		{"slack", "Slack Tokens", "Detects Slack tokens and webhooks", []secretsv1.SecretType{secretsv1.SecretType_SECRET_TYPE_SLACK_TOKEN, secretsv1.SecretType_SECRET_TYPE_SLACK_WEBHOOK}},
		{"stripe", "Stripe Keys", "Detects Stripe API keys", []secretsv1.SecretType{secretsv1.SecretType_SECRET_TYPE_STRIPE_KEY}},
		{"openai", "OpenAI Keys", "Detects OpenAI API keys", []secretsv1.SecretType{secretsv1.SecretType_SECRET_TYPE_OPENAI_KEY}},
		{"anthropic", "Anthropic Keys", "Detects Anthropic API keys", []secretsv1.SecretType{secretsv1.SecretType_SECRET_TYPE_ANTHROPIC_KEY}},
		{"private_key", "Private Keys", "Detects RSA, DSA, EC, and other private keys", []secretsv1.SecretType{secretsv1.SecretType_SECRET_TYPE_PRIVATE_KEY}},
		{"jwt", "JSON Web Tokens", "Detects JWT tokens", []secretsv1.SecretType{secretsv1.SecretType_SECRET_TYPE_JWT}},
		{"generic", "Generic API Keys", "Detects generic API key patterns", []secretsv1.SecretType{secretsv1.SecretType_SECRET_TYPE_GENERIC_API_KEY}},
	}

	var detectors []*secretsv1.DetectorInfo

	// Add built-in detectors
	for _, d := range builtinDetectors {
		detectors = append(detectors, &secretsv1.DetectorInfo{
			Id:          d.id,
			Name:        d.name,
			Description: d.description,
			Types:       d.types,
			Source:      secretsv1.DetectorSource_DETECTOR_SOURCE_BUILTIN,
			Enabled:     true,
		})
	}

	// Add Veles detectors
	velesDetectors := []*secretsv1.DetectorInfo{
		{
			Id:          "veles-gcp-api-key",
			Name:        "Veles GCP API Key",
			Description: "OSV-SCALIBR Veles detector for GCP API keys",
			Types:       []secretsv1.SecretType{secretsv1.SecretType_SECRET_TYPE_GCP_API_KEY},
			Source:      secretsv1.DetectorSource_DETECTOR_SOURCE_VELES,
			Enabled:     true,
		},
		{
			Id:          "veles-gcp-sak",
			Name:        "Veles GCP Service Account Key",
			Description: "OSV-SCALIBR Veles detector for GCP service account keys",
			Types:       []secretsv1.SecretType{secretsv1.SecretType_SECRET_TYPE_GCP_SERVICE_ACCOUNT_KEY},
			Source:      secretsv1.DetectorSource_DETECTOR_SOURCE_VELES,
			Enabled:     true,
		},
		{
			Id:          "veles-rubygems",
			Name:        "Veles RubyGems API Key",
			Description: "OSV-SCALIBR Veles detector for RubyGems API keys",
			Types:       []secretsv1.SecretType{secretsv1.SecretType_SECRET_TYPE_RUBYGEMS_API_KEY},
			Source:      secretsv1.DetectorSource_DETECTOR_SOURCE_VELES,
			Enabled:     true,
		},
	}
	detectors = append(detectors, velesDetectors...)

	// Add custom detectors
	for _, cd := range h.customDetectors {
		detectors = append(detectors, &secretsv1.DetectorInfo{
			Id:          string(cd.Type),
			Name:        cd.Description,
			Description: cd.Description,
			Types:       []secretsv1.SecretType{internalproto.SecretTypeToProto(cd.Type)},
			Source:      secretsv1.DetectorSource_DETECTOR_SOURCE_CUSTOM,
			Enabled:     true,
		})
	}

	return detectors
}

// historyFindingsToProto converts history findings to proto with git context.
func (h *SecretsHandler) historyFindingsToProto(findings []secrets.HistoryFinding) []*secretsv1.Finding {
	if len(findings) == 0 {
		return nil
	}

	out := make([]*secretsv1.Finding, len(findings))
	for i, hf := range findings {
		pf := internalproto.SecretsFindingToProto(hf.Finding)

		// Add git context
		if pf.Location == nil {
			pf.Location = &secretsv1.Location{}
		}
		pf.Location.Source = secretsv1.SecretSource_SECRET_SOURCE_GIT_COMMIT
		pf.Location.GitContext = &secretsv1.GitContext{
			CommitHash:    hf.CommitHash,
			Author:        hf.Author,
			AuthorEmail:   hf.AuthorEmail,
			CommitDate:    hf.CommitDate,
			CommitMessage: hf.CommitMessage,
			RemovedIn:     hf.RemovedIn,
			StillPresent:  hf.StillPresent,
		}

		out[i] = pf
	}
	return out
}
