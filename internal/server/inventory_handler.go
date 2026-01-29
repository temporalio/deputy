package server

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	inventoryv1 "github.com/picatz/deputy/gen/deputy/inventory/v1"
	"github.com/picatz/deputy/gen/deputy/inventory/v1/inventoryv1connect"
	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/inventory/registry"
	"github.com/picatz/deputy/internal/otel"
	protoconv "github.com/picatz/deputy/internal/proto"
	"github.com/picatz/deputy/internal/targets"
)

// InventoryHandler implements the InventoryService gRPC handler.
type InventoryHandler struct {
	localMode    bool
	registry     *registry.Registry
	targetPolicy *targets.RemoteTargetPolicy
}

// Ensure InventoryHandler implements the InventoryServiceHandler interface.
var _ inventoryv1connect.InventoryServiceHandler = (*InventoryHandler)(nil)

// InventoryHandlerOption configures an InventoryHandler.
type InventoryHandlerOption func(*InventoryHandler)

// WithInventoryLocalMode enables local mode for InventoryHandler.
func WithInventoryLocalMode() InventoryHandlerOption {
	return func(h *InventoryHandler) {
		h.localMode = true
	}
}

// WithInventoryTargetPolicy sets the remote target policy for server mode validation.
func WithInventoryTargetPolicy(policy *targets.RemoteTargetPolicy) InventoryHandlerOption {
	return func(h *InventoryHandler) {
		h.targetPolicy = policy
	}
}

// WithInventoryRegistry sets a custom registry for the handler.
// If not set, uses the default global registry.
func WithInventoryRegistry(r *registry.Registry) InventoryHandlerOption {
	return func(h *InventoryHandler) {
		h.registry = r
	}
}

// NewInventoryHandler creates a new Inventory service handler.
func NewInventoryHandler(opts ...InventoryHandlerOption) *InventoryHandler {
	h := &InventoryHandler{
		registry: registry.Default,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// CollectInventory extracts package inventory from a target.
func (h *InventoryHandler) CollectInventory(
	ctx context.Context,
	req *connect.Request[inventoryv1.CollectInventoryRequest],
) (*connect.Response[inventoryv1.CollectInventoryResponse], error) {
	span := otel.SpanFromContext(ctx)

	if err := protoconv.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	target := req.Msg.GetTarget()
	if target == "" {
		err := fmt.Errorf("target is required")
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	span.SetAttributes(otel.AttrTargetPath.String(target))

	// Security: Validate target is accessible from remote server (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTargetWithPolicy(target, h.targetPolicy); err != nil {
			otel.SetSpanError(span, err)
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	// Build inventory options
	opts := inventory.Options{}
	if req.Msg.GetOptions() != nil {
		opts.Ecosystems = req.Msg.Options.GetEcosystems()
		opts.Platform = req.Msg.Options.GetPlatform()
	}

	// Determine ref
	ref := ""
	refProvided := false
	if req.Msg.GetOptions() != nil && req.Msg.GetOptions().GetRef() != "" {
		ref = req.Msg.Options.GetRef()
		refProvided = true
	}

	// Collect inventory
	startTime := time.Now()
	exec, err := h.routeCollection(ctx, target, ref, refProvided, opts)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if exec != nil {
		defer exec.Close()
	}
	durationMs := time.Since(startTime).Milliseconds()

	// Get main modules for filtering out self-references
	var mainModules map[string]bool
	if exec.Workspace != nil {
		mainModules = compare.CollectMainModulesFromWorkspace(exec.Workspace)
	}

	// Filter packages to remove self-references, deduplicate stdlib, and remove duplicate PURLs.
	// PURL deduplication is particularly important for container images where the same package
	// may be reported from multiple layers or extractors.
	packages := protoconv.FilterPackages(exec.Result.Packages, protoconv.FilterOptions{
		ExcludeMainModules: mainModules,
		DeduplicateStdlib:  true,
		DeduplicatePURL:    true,
	})

	// Convert to proto
	direct := exec.Result.Direct
	protoPackages := protoconv.ExtractorPackagesToProto(packages, direct)

	// Build stats
	ecosystemCounts := make(map[string]int32)
	directCount := int32(0)
	transitiveCount := int32(0)

	for _, pkg := range packages {
		eco := pkg.Ecosystem().String()
		if eco != "" {
			ecosystemCounts[eco]++
		}

		purl := pkg.PURL()
		isDirect := false
		if purl != nil && direct != nil {
			isDirect = direct[purl.String()]
		}
		if isDirect {
			directCount++
		} else {
			transitiveCount++
		}
	}

	span.SetAttributes(otel.AttrPackageCount.Int(len(packages)))

	// Build extractors used list
	extractorsUsed := []string{}
	// Note: We could track which extractors produced results, but for now
	// we just list the enabled extractors based on ecosystems

	resp := &inventoryv1.CollectInventoryResponse{
		Target:      protoconv.InventoryTargetToProto(exec.Result.Target),
		GeneratedAt: timestamppb.New(exec.Result.GeneratedAt),
		Packages:    protoPackages,
		Stats: &inventoryv1.InventoryStats{
			TotalPackages:      int32(len(packages)),
			DirectPackages:     directCount,
			TransitivePackages: transitiveCount,
			ByEcosystem:        ecosystemCounts,
			DurationMs:         durationMs,
		},
		ExtractorsUsed: extractorsUsed,
	}

	// Add image info if present
	if exec.Result.ImageInfo != nil {
		resp.ImageInfo = protoconv.ImageInfoToProto(exec.Result.ImageInfo)
	}

	// Add dockerfile info if present
	if exec.Result.DockerfileInfo != nil {
		resp.DockerfileInfo = protoconv.DockerfileInfoToProto(exec.Result.DockerfileInfo)
	}

	return connect.NewResponse(resp), nil
}

// StreamCollectInventory extracts inventory with streaming progress updates.
func (h *InventoryHandler) StreamCollectInventory(
	ctx context.Context,
	req *connect.Request[inventoryv1.CollectInventoryRequest],
	stream *connect.ServerStream[inventoryv1.CollectInventoryProgress],
) error {
	span := otel.SpanFromContext(ctx)

	if err := protoconv.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return connect.NewError(connect.CodeInvalidArgument, err)
	}

	target := req.Msg.GetTarget()
	if target == "" {
		err := fmt.Errorf("target is required")
		otel.SetSpanError(span, err)
		return connect.NewError(connect.CodeInvalidArgument, err)
	}

	span.SetAttributes(otel.AttrTargetPath.String(target))

	// Security: Validate target
	if !h.localMode {
		if err := targets.ValidateRemoteTargetWithPolicy(target, h.targetPolicy); err != nil {
			otel.SetSpanError(span, err)
			return connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	// Send resolving phase
	if err := stream.Send(&inventoryv1.CollectInventoryProgress{
		Phase:   inventoryv1.CollectPhase_PHASE_RESOLVING_TARGET,
		Message: fmt.Sprintf("Resolving target: %s", target),
	}); err != nil {
		return err
	}

	// Build inventory options
	opts := inventory.Options{}
	if req.Msg.GetOptions() != nil {
		opts.Ecosystems = req.Msg.Options.GetEcosystems()
		opts.Platform = req.Msg.Options.GetPlatform()
	}

	ref := ""
	refProvided := false
	if req.Msg.GetOptions() != nil && req.Msg.GetOptions().GetRef() != "" {
		ref = req.Msg.Options.GetRef()
		refProvided = true
	}

	// Send extracting phase
	if err := stream.Send(&inventoryv1.CollectInventoryProgress{
		Phase:   inventoryv1.CollectPhase_PHASE_EXTRACTING,
		Message: "Extracting packages...",
	}); err != nil {
		return err
	}

	// Collect inventory
	startTime := time.Now()
	exec, err := h.routeCollection(ctx, target, ref, refProvided, opts)
	if err != nil {
		otel.SetSpanError(span, err)
		if sendErr := stream.Send(&inventoryv1.CollectInventoryProgress{
			Phase: inventoryv1.CollectPhase_PHASE_FAILED,
			Error: err.Error(),
		}); sendErr != nil {
			return sendErr
		}
		return connect.NewError(connect.CodeInternal, err)
	}
	if exec != nil {
		defer exec.Close()
	}
	durationMs := time.Since(startTime).Milliseconds()

	// Get main modules for filtering out self-references
	var streamMainModules map[string]bool
	if exec.Workspace != nil {
		streamMainModules = compare.CollectMainModulesFromWorkspace(exec.Workspace)
	}

	// Filter packages to remove self-references, deduplicate stdlib, and remove duplicate PURLs.
	packages := protoconv.FilterPackages(exec.Result.Packages, protoconv.FilterOptions{
		ExcludeMainModules: streamMainModules,
		DeduplicateStdlib:  true,
		DeduplicatePURL:    true,
	})

	// Convert to proto
	direct := exec.Result.Direct
	protoPackages := protoconv.ExtractorPackagesToProto(packages, direct)

	// Build stats
	ecosystemCounts := make(map[string]int32)
	directCount := int32(0)
	transitiveCount := int32(0)

	for _, pkg := range packages {
		eco := pkg.Ecosystem().String()
		if eco != "" {
			ecosystemCounts[eco]++
		}

		purl := pkg.PURL()
		isDirect := false
		if purl != nil && direct != nil {
			isDirect = direct[purl.String()]
		}
		if isDirect {
			directCount++
		} else {
			transitiveCount++
		}
	}

	span.SetAttributes(otel.AttrPackageCount.Int(len(packages)))

	resp := &inventoryv1.CollectInventoryResponse{
		Target:      protoconv.InventoryTargetToProto(exec.Result.Target),
		GeneratedAt: timestamppb.New(exec.Result.GeneratedAt),
		Packages:    protoPackages,
		Stats: &inventoryv1.InventoryStats{
			TotalPackages:      int32(len(packages)),
			DirectPackages:     directCount,
			TransitivePackages: transitiveCount,
			ByEcosystem:        ecosystemCounts,
			DurationMs:         durationMs,
		},
	}

	// Add image info if present
	if exec.Result.ImageInfo != nil {
		resp.ImageInfo = protoconv.ImageInfoToProto(exec.Result.ImageInfo)
	}

	// Add dockerfile info if present
	if exec.Result.DockerfileInfo != nil {
		resp.DockerfileInfo = protoconv.DockerfileInfoToProto(exec.Result.DockerfileInfo)
	}

	// Send completed phase with result
	return stream.Send(&inventoryv1.CollectInventoryProgress{
		Phase:         inventoryv1.CollectPhase_PHASE_COMPLETED,
		Message:       fmt.Sprintf("Found %d packages", len(packages)),
		PackagesFound: int32(len(packages)),
		Result:        resp,
	})
}

// ListExtractors returns available inventory extractors.
func (h *InventoryHandler) ListExtractors(
	ctx context.Context,
	req *connect.Request[inventoryv1.ListExtractorsRequest],
) (*connect.Response[inventoryv1.ListExtractorsResponse], error) {
	span := otel.SpanFromContext(ctx)

	if err := protoconv.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	extractors := h.registry.ListAll()

	return connect.NewResponse(&inventoryv1.ListExtractorsResponse{
		Extractors: extractors,
	}), nil
}

// RegisterExtractor registers a proto-based extractor plugin.
func (h *InventoryHandler) RegisterExtractor(
	ctx context.Context,
	req *connect.Request[inventoryv1.RegisterExtractorRequest],
) (*connect.Response[inventoryv1.RegisterExtractorResponse], error) {
	span := otel.SpanFromContext(ctx)

	// Security: RegisterExtractor requires local mode since plugins run locally
	if !h.localMode {
		return nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("RegisterExtractor is not available on remote servers"))
	}

	if err := protoconv.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	info := req.Msg.GetInfo()
	if info == nil {
		err := fmt.Errorf("extractor info is required")
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	pluginAddress := req.Msg.GetPluginAddress()
	if pluginAddress == "" {
		err := fmt.Errorf("plugin address is required")
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// Mark source as plugin
	info.Source = inventoryv1.ExtractorSource_EXTRACTOR_SOURCE_PLUGIN

	if err := h.registry.Register(info, pluginAddress); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeAlreadyExists, err)
	}

	return connect.NewResponse(&inventoryv1.RegisterExtractorResponse{
		Registered: true,
	}), nil
}

// UnregisterExtractor removes a previously registered plugin.
func (h *InventoryHandler) UnregisterExtractor(
	ctx context.Context,
	req *connect.Request[inventoryv1.UnregisterExtractorRequest],
) (*connect.Response[inventoryv1.UnregisterExtractorResponse], error) {
	span := otel.SpanFromContext(ctx)

	// Security: UnregisterExtractor requires local mode since plugins run locally
	if !h.localMode {
		return nil, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("UnregisterExtractor is not available on remote servers"))
	}

	if err := protoconv.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	name := req.Msg.GetName()
	if name == "" {
		err := fmt.Errorf("extractor name is required")
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	unregistered := h.registry.Unregister(name)

	return connect.NewResponse(&inventoryv1.UnregisterExtractorResponse{
		Unregistered: unregistered,
	}), nil
}

// routeCollection routes to the appropriate inventory collector based on target type.
func (h *InventoryHandler) routeCollection(ctx context.Context, target, ref string, refProvided bool, opts inventory.Options) (*inventory.Execution, error) {
	kind := targets.DetectKind(target)

	switch kind {
	case targets.KindContainerImage:
		targetOpts := &targets.OpenOptions{}
		if opts.Platform != "" {
			targetOpts.Platform = opts.Platform
		}
		return inventory.CollectContainerImage(ctx, target, targetOpts, inventory.Options{Ecosystems: opts.Ecosystems})

	case targets.KindDockerfile:
		return inventory.CollectDockerfile(ctx, target, inventory.Options{Ecosystems: opts.Ecosystems})

	default:
		return inventory.CollectRepository(ctx, target, ref, refProvided, inventory.Options{Ecosystems: opts.Ecosystems})
	}
}
