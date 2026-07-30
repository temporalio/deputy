package server

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	graphv1 "github.com/temporalio/deputy/gen/deputy/graph/v1"
	"github.com/temporalio/deputy/gen/deputy/graph/v1/graphv1connect"
	"github.com/temporalio/deputy/internal/dependency/graph"
	"github.com/temporalio/deputy/internal/dependency/graphquery"
	"github.com/temporalio/deputy/internal/gitutil"
	"github.com/temporalio/deputy/internal/inventory"
	"github.com/temporalio/deputy/internal/otel"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/targets"
)

// GraphHandler implements the GraphService gRPC handler.
type GraphHandler struct {
	localMode    bool // Skip remote target validation for in-process usage
	targetPolicy *targets.RemoteTargetPolicy
}

// Ensure GraphHandler implements the GraphServiceHandler interface.
var _ graphv1connect.GraphServiceHandler = (*GraphHandler)(nil)

// GraphHandlerOption configures a GraphHandler.
type GraphHandlerOption func(*GraphHandler)

// WithGraphLocalMode enables local mode which skips remote target validation.
// Use this for in-process clients that need to access local filesystems.
func WithGraphLocalMode() GraphHandlerOption {
	return func(h *GraphHandler) {
		h.localMode = true
	}
}

// WithGraphTargetPolicy sets the remote target policy for server mode validation.
func WithGraphTargetPolicy(policy *targets.RemoteTargetPolicy) GraphHandlerOption {
	return func(h *GraphHandler) {
		h.targetPolicy = policy
	}
}

// NewGraphHandler creates a new Graph service handler.
func NewGraphHandler(opts ...GraphHandlerOption) *GraphHandler {
	h := &GraphHandler{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// BuildGraph constructs a dependency graph for a target.
func (h *GraphHandler) BuildGraph(
	ctx context.Context,
	req *connect.Request[graphv1.BuildGraphRequest],
) (*connect.Response[graphv1.BuildGraphResponse], error) {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	target := req.Msg.GetTarget()
	if target == "" {
		target = "."
	}

	// Add business attributes to the otelconnect span
	span.SetAttributes(otel.AttrTargetPath.String(target))

	// Security: Validate target is accessible from remote server (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTargetWithPolicy(target, h.targetPolicy); err != nil {
			otel.SetSpanError(span, err)
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	opts, ref, refProvided, kind := graphInventoryOptions(req.Msg.Options)

	// Collect inventory
	exec, err := h.collectInventory(ctx, target, ref, refProvided, kind, opts)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to collect inventory: %w", err))
	}
	if exec != nil {
		defer exec.Close()
	}

	// Build graph with edge resolution
	builder := graph.NewBuilder(graphBuilderOptions(req.Msg.Options))

	// Use workspace for edge resolution if available
	var g *graph.Graph
	if exec.Workspace != nil {
		g, err = builder.BuildFromWorkspace(ctx, exec.Result.Packages, exec.Result.Direct, nil, nil, exec.Workspace)
	} else {
		// Fallback to basic graph without edge resolution
		g = graph.FromInventory(exec.Result.Packages, exec.Result.Direct)
		g.UpdateDepths()
	}
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to build graph: %w", err))
	}

	// Extended mode: add declared-only dependencies from full module graph
	if req.Msg.Options != nil && req.Msg.Options.Extended {
		h.mergeExtendedGraph(ctx, target, exec.Workspace != nil, g)
	}

	// Record graph stats on span
	span.SetAttributes(otel.AttrPackageCount.Int(len(g.GetNodesSlice())))

	response := &graphv1.BuildGraphResponse{
		Target:      internalproto.InventoryTargetToProto(exec.Result.Target),
		GeneratedAt: timestamppb.Now(),
		Nodes:       g.GetNodesSlice(),
		Edges:       g.GetEdgesSlice(),
		Roots:       g.GetRoots(),
		Stats:       g.Stats(),
	}

	return connect.NewResponse(response), nil
}

func graphInventoryOptions(options *graphv1.GraphOptions) (inventory.Options, string, bool, targets.Kind) {
	opts := inventory.Options{}
	if options == nil {
		return opts, "", false, targets.KindUnspecified
	}
	opts.Ecosystems = options.GetEcosystems()
	opts.Platform = options.GetPlatform()
	opts.ExcludePaths = options.GetExcludePaths()

	ref := strings.TrimSpace(options.GetRef())
	refProvided := ref != ""
	return opts, ref, refProvided, targets.Kind(options.GetTargetHint())
}

// collectInventory collects inventory from target using the same ref semantics as
// list and scan: explicit snapshot refs are materialized, while HEAD/WORKING
// refs keep local working-tree behavior.
func (h *GraphHandler) collectInventory(ctx context.Context, target, ref string, refProvided bool, kind targets.Kind, opts inventory.Options) (*inventory.Execution, error) {
	if kind == targets.KindUnspecified {
		kind = targets.DetectKind(target)
	}
	switch kind {
	case targets.KindContainerImage:
		targetOpts := map[string]string{}
		if opts.Platform != "" {
			targetOpts["platform"] = opts.Platform
		}
		return inventory.CollectContainerImage(ctx, target, targetOpts, opts)

	case targets.KindDir:
		if refProvided && ref != "" && !gitutil.IsWorkingTreeRef(ref) {
			return inventory.CollectRepositoryAtRef(ctx, target, ref, opts)
		}
		return inventory.CollectDirectory(ctx, target, opts)

	case targets.KindGit:
		if refProvided && ref != "" && !gitutil.IsWorkingTreeRef(ref) {
			return inventory.CollectRepositoryAtRef(ctx, target, ref, opts)
		}
		return inventory.CollectRepository(ctx, target, graphRefOrHEAD(ref), refProvided, opts)

	default:
		if refProvided && ref != "" && !gitutil.IsWorkingTreeRef(ref) {
			return inventory.CollectRepositoryAtRef(ctx, target, ref, opts)
		}
		return inventory.CollectRepository(ctx, target, graphRefOrHEAD(ref), refProvided, opts)
	}
}

func graphRefOrHEAD(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "HEAD"
	}
	return ref
}

// graphBuilderOptions maps request options onto builder options. Resolution is
// local-only by default: deps.dev transitive resolution deliberately rides the
// use_proxy opt-in (a behavior change from the pre-refactor handlers, which
// always reached deps.dev), so a default build makes no network calls. Pinned
// by TestGraphBuilderOptions.
func graphBuilderOptions(opts *graphv1.GraphOptions) graph.BuilderOptions {
	if opts == nil {
		return graph.BuilderOptions{}
	}
	return graph.BuilderOptions{
		UseProxy:              opts.GetUseProxy(),
		UseGit:                opts.GetUseGit(),
		PrivatePatterns:       slices.Clone(opts.GetPrivatePatterns()),
		UseDepsDevTransitives: opts.GetUseProxy(),
	}
}

func (h *GraphHandler) mergeExtendedGraph(ctx context.Context, target string, hasWorkspace bool, g *graph.Graph) {
	// Only works for local directories with Go modules currently. Remote server
	// mode rejects local targets before this point.
	if g == nil || !hasWorkspace || !targets.IsLocalTarget(target) {
		return
	}
	extResult, err := graph.AnalyzeExtendedGraph(ctx, target)
	if err == nil && extResult != nil {
		graph.MergeExtendedIntoGraph(g, extResult)
	}
	// Non-fatal: if extended analysis fails, callers still return the standard graph.
}

// WhyDependency finds paths explaining why a dependency exists.
func (h *GraphHandler) WhyDependency(
	ctx context.Context,
	req *connect.Request[graphv1.WhyDependencyRequest],
) (*connect.Response[graphv1.WhyDependencyResponse], error) {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	target := req.Msg.GetTarget()
	if target == "" {
		target = "."
	}

	dependency := req.Msg.GetDependency()
	if dependency == "" {
		err := fmt.Errorf("dependency is required")
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	// Add business attributes to the otelconnect span
	span.SetAttributes(
		otel.AttrTargetPath.String(target),
		otel.AttrMCPGraphPackage.String(dependency),
	)

	// Security: Validate target is accessible from remote server (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTargetWithPolicy(target, h.targetPolicy); err != nil {
			otel.SetSpanError(span, err)
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	opts, ref, refProvided, kind := graphInventoryOptions(req.Msg.Options)

	// Collect inventory
	exec, err := h.collectInventory(ctx, target, ref, refProvided, kind, opts)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to collect inventory: %w", err))
	}
	if exec != nil {
		defer exec.Close()
	}

	// Build graph with edge resolution
	builder := graph.NewBuilder(graphBuilderOptions(req.Msg.Options))

	// Use workspace for edge resolution if available
	var g *graph.Graph
	if exec.Workspace != nil {
		g, err = builder.BuildFromWorkspace(ctx, exec.Result.Packages, exec.Result.Direct, nil, nil, exec.Workspace)
	} else {
		// Fallback to basic graph without edge resolution
		g = graph.FromInventory(exec.Result.Packages, exec.Result.Direct)
		g.UpdateDepths()
	}
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to build graph: %w", err))
	}
	if req.Msg.Options != nil && req.Msg.Options.Extended {
		h.mergeExtendedGraph(ctx, target, exec.Workspace != nil, g)
	}

	// Find matching dependency nodes
	matches := findMatchingNodes(g, dependency)
	var targetNode *graph.Node
	if len(matches) > 0 {
		targetNode = matches[0]
	}

	response := &graphv1.WhyDependencyResponse{
		Target:     internalproto.InventoryTargetToProto(exec.Result.Target),
		Dependency: dependency,
		Found:      targetNode != nil,
	}

	// Add warning if multiple packages matched the query
	if len(matches) > 1 {
		// Only show alternatives if there are other high-quality matches (score >= 2)
		// This avoids showing noisy substring matches as suggestions
		queryLower := strings.ToLower(dependency)
		var goodAlternatives []string
		for i := 1; i < len(matches) && len(goodAlternatives) < 3; i++ {
			if matchScore(matches[i].Name, queryLower) >= 2 {
				goodAlternatives = append(goodAlternatives, lastNSegments(matches[i].Name, 2))
			}
		}

		if len(goodAlternatives) > 0 {
			// There are other good matches - suggest them
			hint := fmt.Sprintf("%d packages match %q. Also try:", len(matches), dependency)
			response.Warnings = append(response.Warnings, hint)
			for _, alt := range goodAlternatives {
				response.Warnings = append(response.Warnings, fmt.Sprintf("  → %s", alt))
			}
		} else if len(matches) > 5 {
			// Many matches but none are great - just mention --list
			hint := fmt.Sprintf("%d packages match %q. Use --list to see all.", len(matches), dependency)
			response.Warnings = append(response.Warnings, hint)
		}
		// For 2-5 matches with no great alternatives, don't show a warning at all
		// The user got what they wanted
	}

	if targetNode != nil {
		// Find paths from roots to the target
		paths := g.PathsTo(targetNode.Purl)
		response.Paths = graph.PathsToProto(paths)
		response.Dependency = targetNode.Purl
		response.DependencyNode = targetNode
		if len(paths) == 0 {
			response.Message = graphquery.NoDependencyPathMessage(
				targetNode,
				req.Msg.GetOptions().GetUseProxy() || req.Msg.GetOptions().GetUseGit(),
				req.Msg.GetOptions().GetExtended(),
			)
		}

		// Record results on span
		span.SetAttributes(
			otel.AttrMCPGraphFound.Bool(true),
			otel.AttrMCPGraphDirect.Bool(targetNode.Direct),
			otel.AttrMCPGraphPathCount.Int(len(paths)),
		)
	} else {
		response.Message = fmt.Sprintf("Package %q not found in dependency graph", dependency)
		span.SetAttributes(otel.AttrMCPGraphFound.Bool(false))
	}

	return connect.NewResponse(response), nil
}

// QueryGraph returns a filtered subset of a dependency graph.
func (h *GraphHandler) QueryGraph(
	ctx context.Context,
	req *connect.Request[graphv1.QueryGraphRequest],
) (*connect.Response[graphv1.QueryGraphResponse], error) {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := internalproto.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	target := req.Msg.GetTarget()
	if target == "" {
		target = "."
	}

	// Add business attributes to the otelconnect span
	span.SetAttributes(otel.AttrTargetPath.String(target))

	// Security: Validate target is accessible from remote server (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTargetWithPolicy(target, h.targetPolicy); err != nil {
			otel.SetSpanError(span, err)
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	opts, ref, refProvided, kind := graphInventoryOptions(req.Msg.Options)

	// Collect inventory
	exec, err := h.collectInventory(ctx, target, ref, refProvided, kind, opts)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to collect inventory: %w", err))
	}
	if exec != nil {
		defer exec.Close()
	}

	// Build graph from inventory
	g := graph.FromInventory(exec.Result.Packages, exec.Result.Direct)
	g.UpdateDepths()
	if req.Msg.Options != nil && req.Msg.Options.Extended {
		h.mergeExtendedGraph(ctx, target, exec.Workspace != nil, g)
	}

	// Apply filters if specified
	if req.Msg.Filter != nil {
		filter := req.Msg.Filter

		// Filter by subgraph root
		if filter.RootPurl != "" {
			g = g.Subgraph(filter.RootPurl)
		}

		// Filter by predicate
		g = g.Filter(func(n *graph.Node) bool {
			// Ecosystem filter
			if len(filter.Ecosystems) > 0 {
				found := false
				for _, eco := range filter.Ecosystems {
					if strings.EqualFold(n.Ecosystem, eco) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}

			// Depth filters
			if filter.MinDepth > 0 && n.Depth < filter.MinDepth {
				return false
			}
			if filter.MaxDepth > 0 && n.Depth > filter.MaxDepth {
				return false
			}

			// Direct/transitive filters
			if filter.OnlyDirect && !n.Direct {
				return false
			}
			if filter.OnlyTransitive && n.Direct {
				return false
			}

			// Vulnerable filter
			if filter.OnlyVulnerable && n.GetVulnerabilityCount().GetTotal() == 0 {
				return false
			}

			// Name pattern filter
			if filter.NamePattern != "" {
				matched, _ := filepath.Match(filter.NamePattern, n.Name)
				if !matched {
					return false
				}
			}

			return true
		})
	}

	// Record filtered graph stats on span
	span.SetAttributes(otel.AttrPackageCount.Int(len(g.GetNodesSlice())))

	response := &graphv1.QueryGraphResponse{
		Target: internalproto.InventoryTargetToProto(exec.Result.Target),
		Nodes:  g.GetNodesSlice(),
		Edges:  g.GetEdgesSlice(),
		Stats:  g.Stats(),
	}

	return connect.NewResponse(response), nil
}

// findMatchingNodes finds nodes matching the query pattern.
// Supports glob patterns via path.Match or simple substring matching.
// Results are sorted with best matches first: exact matches, then final segment
// matches, then substring matches, all sorted alphabetically within each tier.
//
// Examples:
//   - "cobra" matches any package containing "cobra", prefers github.com/spf13/cobra
//   - "*/cobra" matches packages ending with /cobra
//   - "spf13/*" matches all packages under spf13
func findMatchingNodes(g *graph.Graph, query string) []*graph.Node {
	return graphquery.FindMatchingNodes(g, query)
}

// lastNSegments returns the last n segments of a package path.
// E.g., lastNSegments("github.com/go-git/go-git/v5", 2) returns "go-git/v5"
func lastNSegments(name string, n int) string {
	parts := strings.Split(name, "/")
	if len(parts) <= n {
		return name
	}
	return strings.Join(parts[len(parts)-n:], "/")
}

// matchScore returns a quality score for how well a package name matches a query.
// Higher scores indicate better matches:
//   - 3: exact match (name equals query)
//   - 2: final segment match (query matches the last path component)
//   - 1: substring match
func matchScore(name, queryLower string) int {
	return graphquery.NameMatchScore(name, queryLower)
}
