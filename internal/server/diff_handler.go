package server

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	"github.com/temporalio/deputy/gen/deputy/diff/v1/diffv1connect"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/inventory"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/scanning"
	"github.com/temporalio/deputy/internal/targets"
)

// DiffHandler implements the DiffService gRPC handler.
type DiffHandler struct {
	localMode    bool
	targetPolicy *targets.RemoteTargetPolicy
}

// Ensure DiffHandler implements the DiffServiceHandler interface.
var _ diffv1connect.DiffServiceHandler = (*DiffHandler)(nil)

// DiffHandlerOption configures a DiffHandler.
type DiffHandlerOption func(*DiffHandler)

// WithDiffLocalMode enables local mode for DiffHandler.
func WithDiffLocalMode() DiffHandlerOption {
	return func(h *DiffHandler) {
		h.localMode = true
	}
}

// WithDiffTargetPolicy sets the remote target policy for server mode validation.
func WithDiffTargetPolicy(policy *targets.RemoteTargetPolicy) DiffHandlerOption {
	return func(h *DiffHandler) {
		h.targetPolicy = policy
	}
}

// NewDiffHandler creates a new Diff service handler.
func NewDiffHandler(opts ...DiffHandlerOption) *DiffHandler {
	h := &DiffHandler{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// DiffPackages compares dependencies between two targets.
func (h *DiffHandler) DiffPackages(
	ctx context.Context,
	req *connect.Request[diffv1.DiffPackagesRequest],
) (*connect.Response[diffv1.DiffPackagesResponse], error) {
	if err := internalproto.Validate(req.Msg); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	baseTarget := req.Msg.GetBaseTarget()
	targetTarget := req.Msg.GetTargetTarget()

	if baseTarget == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("base_target is required"))
	}
	if targetTarget == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target_target is required"))
	}

	// Security: Validate targets are accessible from remote server (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTargetWithPolicy(baseTarget, h.targetPolicy); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid base_target: %w", err))
		}
		if err := targets.ValidateRemoteTargetWithPolicy(targetTarget, h.targetPolicy); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid target_target: %w", err))
		}
	}

	// Build inventory options
	opts := inventory.Options{}
	if req.Msg.Options != nil {
		opts.Ecosystems = req.Msg.Options.Ecosystems
		opts.Platform = req.Msg.Options.Platform
		opts.ExcludePaths = req.Msg.Options.GetExcludePaths()
	}

	// Collect inventory from base target
	baseExec, err := h.collectInventory(ctx, baseTarget, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to collect base inventory: %w", err))
	}
	if baseExec != nil {
		defer baseExec.Close()
	}

	// Collect inventory from target target
	targetExec, err := h.collectInventory(ctx, targetTarget, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to collect target inventory: %w", err))
	}
	if targetExec != nil {
		defer targetExec.Close()
	}

	// Compare packages
	changes := compare.ComparePackages(
		baseExec.Result.Packages,
		targetExec.Result.Packages,
		baseExec.Result.Direct,
		nil, // pkgDirect
		nil, // workspace
	)

	// Build response
	response := &diffv1.DiffPackagesResponse{
		BaseTarget: &targetv1.Target{
			Kind:        baseExec.Result.Target.Kind,
			DisplayPath: baseExec.Result.Target.DisplayPath,
		},
		TargetTarget: &targetv1.Target{
			Kind:        targetExec.Result.Target.Kind,
			DisplayPath: targetExec.Result.Target.DisplayPath,
		},
		GeneratedAt: timestamppb.Now(),
		Changes:     internalproto.PackageChangesToProto(changes),
		Stats:       internalproto.DiffStatsToProto(changes),
	}

	return connect.NewResponse(response), nil
}

// collectInventory collects inventory from a target.
func (h *DiffHandler) collectInventory(ctx context.Context, target string, opts inventory.Options) (*inventory.Execution, error) {
	kind := targets.DetectKind(target)

	switch kind {
	case targets.KindContainerImage:
		targetOpts := map[string]string{}
		if opts.Platform != "" {
			targetOpts["platform"] = opts.Platform
		}
		return inventory.CollectContainerImage(ctx, target, targetOpts, opts)

	case targets.KindDir:
		return inventory.CollectDirectory(ctx, target, opts)

	case targets.KindGit:
		return inventory.CollectRepository(ctx, target, "HEAD", false, opts)

	default:
		return inventory.CollectRepository(ctx, target, "HEAD", false, opts)
	}
}

// DiffVulnerabilities compares vulnerabilities between two targets.
func (h *DiffHandler) DiffVulnerabilities(
	ctx context.Context,
	req *connect.Request[diffv1.DiffVulnerabilitiesRequest],
) (*connect.Response[diffv1.DiffVulnerabilitiesResponse], error) {
	if err := internalproto.Validate(req.Msg); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	baseTarget := req.Msg.GetBaseTarget()
	targetTarget := req.Msg.GetTargetTarget()

	if baseTarget == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("base_target is required"))
	}
	if targetTarget == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target_target is required"))
	}

	// Security: Validate targets are accessible from remote server (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTargetWithPolicy(baseTarget, h.targetPolicy); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid base_target: %w", err))
		}
		if err := targets.ValidateRemoteTargetWithPolicy(targetTarget, h.targetPolicy); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid target_target: %w", err))
		}
	}

	// Build scan options
	opts := scanning.Options{}
	if req.Msg.ScanOptions != nil {
		opts.Ecosystems = req.Msg.ScanOptions.Ecosystems
		opts.ExcludePaths = req.Msg.ScanOptions.GetExcludePaths()
	}

	// Scan base target using scanning package
	baseExec, err := scanning.Scan(ctx, baseTarget, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to scan base target: %w", err))
	}
	if baseExec != nil {
		defer baseExec.Close()
	}

	// Scan target target
	targetExec, err := scanning.Scan(ctx, targetTarget, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to scan target target: %w", err))
	}
	if targetExec != nil {
		defer targetExec.Close()
	}

	// Build vulnerability ID sets for comparison
	baseVulnIDs := make(map[string]bool)
	for _, f := range baseExec.Result.Findings {
		baseVulnIDs[f.AdvisoryID] = true
	}

	targetVulnIDs := make(map[string]bool)
	for _, f := range targetExec.Result.Findings {
		targetVulnIDs[f.AdvisoryID] = true
	}

	// Find added vulnerabilities (in target but not in base)
	var addedFindings []*vulnerabilityv1.Finding
	addedBySeverity := make(map[string]int32)
	for _, f := range targetExec.Result.Findings {
		if !baseVulnIDs[f.AdvisoryID] {
			adv := targetExec.Result.Advisories[f.AdvisoryID]
			protoFinding := internalproto.FindingToProto(f, adv)
			addedFindings = append(addedFindings, protoFinding)
			if adv != nil && adv.Severity != nil {
				addedBySeverity[adv.Severity.Level.String()]++
			}
		}
	}

	// Find removed vulnerabilities (in base but not in target)
	var removedFindings []*vulnerabilityv1.Finding
	removedBySeverity := make(map[string]int32)
	for _, f := range baseExec.Result.Findings {
		if !targetVulnIDs[f.AdvisoryID] {
			adv := baseExec.Result.Advisories[f.AdvisoryID]
			protoFinding := internalproto.FindingToProto(f, adv)
			removedFindings = append(removedFindings, protoFinding)
			if adv != nil && adv.Severity != nil {
				removedBySeverity[adv.Severity.Level.String()]++
			}
		}
	}

	// Merge advisories from both scans
	mergedAdvisories := make(map[string]*vulnerabilityv1.Advisory)
	for id, adv := range baseExec.Result.Advisories {
		mergedAdvisories[id] = adv
	}
	for id, adv := range targetExec.Result.Advisories {
		mergedAdvisories[id] = adv
	}

	// Build response
	response := &diffv1.DiffVulnerabilitiesResponse{
		BaseTarget: &targetv1.Target{
			Kind:        baseExec.Result.Target.Kind,
			DisplayPath: baseExec.Result.Target.DisplayPath,
		},
		TargetTarget: &targetv1.Target{
			Kind:        targetExec.Result.Target.Kind,
			DisplayPath: targetExec.Result.Target.DisplayPath,
		},
		GeneratedAt:            timestamppb.Now(),
		AddedVulnerabilities:   addedFindings,
		RemovedVulnerabilities: removedFindings,
		Advisories:             internalproto.AdvisoriesToProto(mergedAdvisories),
		Stats: &diffv1.VulnerabilityDiffStats{
			AddedCount:        int32(len(addedFindings)),
			RemovedCount:      int32(len(removedFindings)),
			AddedBySeverity:   addedBySeverity,
			RemovedBySeverity: removedBySeverity,
		},
	}

	return connect.NewResponse(response), nil
}

// DiffContainerImages performs a comprehensive diff between two container images.
//
// SECURITY: This method can access local Docker daemon when transport is "daemon".
// Local transports (docker-daemon://, tarball://, oci-archive://) require localMode.
func (h *DiffHandler) DiffContainerImages(ctx context.Context, req *connect.Request[diffv1.DiffContainerImagesRequest]) (*connect.Response[diffv1.DiffContainerImagesResponse], error) {
	if err := internalproto.Validate(req.Msg); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	baseImage := req.Msg.BaseImage
	targetImage := req.Msg.TargetImage

	if baseImage == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("base_image is required"))
	}
	if targetImage == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target_image is required"))
	}

	opts := req.Msg.Options
	if opts == nil {
		opts = &diffv1.ContainerDiffOptions{}
	}

	// Security: Block local transports on remote servers
	if !h.localMode {
		transport := strings.ToLower(opts.ImageTransport)
		if transport == "daemon" || transport == "docker-daemon" {
			return nil, connect.NewError(connect.CodePermissionDenied,
				fmt.Errorf("docker-daemon transport is not available on remote servers; use remote registry references"))
		}
		// Validate both image references don't use local schemes
		if err := targets.ValidateRemoteTargetWithPolicy(baseImage, h.targetPolicy); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid base_image: %w", err))
		}
		if err := targets.ValidateRemoteTargetWithPolicy(targetImage, h.targetPolicy); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid target_image: %w", err))
		}
	}

	// Build scan options
	scanOpts := scanning.Options{}
	if opts.ScanOptions != nil {
		scanOpts.Ecosystems = opts.ScanOptions.Ecosystems
		scanOpts.ExcludePaths = opts.ScanOptions.GetExcludePaths()
	}

	// Normalize image references based on transport
	baseRef := normalizeContainerImageRef(baseImage, opts.ImageTransport)
	targetRef := normalizeContainerImageRef(targetImage, opts.ImageTransport)

	// Scan both images in parallel
	type scanResult struct {
		exec *scanning.Execution
		err  error
	}

	baseCh := make(chan scanResult, 1)
	targetCh := make(chan scanResult, 1)

	go func() {
		exec, err := scanning.ScanContainerImage(ctx, baseRef, nil, scanOpts)
		baseCh <- scanResult{exec: exec, err: err}
	}()

	go func() {
		exec, err := scanning.ScanContainerImage(ctx, targetRef, nil, scanOpts)
		targetCh <- scanResult{exec: exec, err: err}
	}()

	// Wait for both scans
	baseRes := <-baseCh
	targetRes := <-targetCh

	if baseRes.err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("scan base image %q: %w", baseRef, baseRes.err))
	}
	if targetRes.err != nil {
		if baseRes.exec != nil {
			baseRes.exec.Close()
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("scan target image %q: %w", targetRef, targetRes.err))
	}

	defer baseRes.exec.Close()
	defer targetRes.exec.Close()

	// Build the response using the scanning results
	response := internalproto.BuildContainerDiffResponseFromScanning(&baseRes.exec.Result, &targetRes.exec.Result)

	return connect.NewResponse(response), nil
}

// normalizeContainerImageRef ensures the image reference has the appropriate scheme.
func normalizeContainerImageRef(ref, transport string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ref
	}
	// Already has a scheme - respect it
	if strings.Contains(ref, "://") {
		return ref
	}
	// Add appropriate prefix based on transport
	switch strings.ToLower(transport) {
	case "daemon", "docker-daemon":
		return "docker-daemon://" + ref
	default:
		return "oci://" + ref
	}
}
