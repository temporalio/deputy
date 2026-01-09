package server

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	graphv1 "github.com/picatz/deputy/gen/deputy/graph/v1"
	"github.com/picatz/deputy/gen/deputy/graph/v1/graphv1connect"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	"github.com/picatz/deputy/internal/dependency/graph"
	"github.com/picatz/deputy/internal/inventory"
	internalproto "github.com/picatz/deputy/internal/proto"
	"github.com/picatz/deputy/internal/targets"
)

// GraphHandler implements the GraphService gRPC handler.
type GraphHandler struct {
	localMode bool // Skip remote target validation for in-process usage
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
	target := req.Msg.GetTarget()
	if target == "" {
		target = "."
	}

	// Security: Validate target is accessible from remote server (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTarget(target); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	// Build inventory options
	opts := inventory.Options{}
	if req.Msg.Options != nil {
		opts.Ecosystems = req.Msg.Options.Ecosystems
		opts.Platform = req.Msg.Options.Platform
	}

	// Collect inventory
	exec, err := h.collectInventory(ctx, target, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to collect inventory: %w", err))
	}
	if exec != nil {
		defer exec.Close()
	}

	// Build graph from inventory
	g := graph.FromInventory(exec.Result.Packages, exec.Result.Direct)
	g.UpdateDepths()

	// Convert to proto
	nodes, edges, roots := internalproto.GraphToProto(g)

	response := &graphv1.BuildGraphResponse{
		Target: &targetv1.Target{
			Kind:        exec.Result.Target.Kind,
			DisplayPath: exec.Result.Target.DisplayPath,
		},
		GeneratedAt: timestamppb.Now(),
		Nodes:       nodes,
		Edges:       edges,
		Roots:       roots,
		Stats:       internalproto.GraphStatsToProto(g.Stats()),
	}

	return connect.NewResponse(response), nil
}

// collectInventory collects inventory from a target.
func (h *GraphHandler) collectInventory(ctx context.Context, target string, opts inventory.Options) (*inventory.Execution, error) {
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

// WhyDependency finds paths explaining why a dependency exists.
func (h *GraphHandler) WhyDependency(
	ctx context.Context,
	req *connect.Request[graphv1.WhyDependencyRequest],
) (*connect.Response[graphv1.WhyDependencyResponse], error) {
	target := req.Msg.GetTarget()
	if target == "" {
		target = "."
	}

	dependency := req.Msg.GetDependency()
	if dependency == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("dependency is required"))
	}

	// Security: Validate target is accessible from remote server (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTarget(target); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	// Build inventory options
	opts := inventory.Options{}
	if req.Msg.Options != nil {
		opts.Ecosystems = req.Msg.Options.Ecosystems
		opts.Platform = req.Msg.Options.Platform
	}

	// Collect inventory
	exec, err := h.collectInventory(ctx, target, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to collect inventory: %w", err))
	}
	if exec != nil {
		defer exec.Close()
	}

	// Build graph from inventory
	g := graph.FromInventory(exec.Result.Packages, exec.Result.Direct)
	g.UpdateDepths()

	// Find the dependency node
	var targetNode *graph.Node
	for n := range g.Nodes() {
		if strings.EqualFold(n.Name, dependency) ||
			strings.EqualFold(n.PURL, dependency) ||
			strings.Contains(strings.ToLower(n.Name), strings.ToLower(dependency)) {
			targetNode = n
			break
		}
	}

	response := &graphv1.WhyDependencyResponse{
		Target: &targetv1.Target{
			Kind:        exec.Result.Target.Kind,
			DisplayPath: exec.Result.Target.DisplayPath,
		},
		Dependency: dependency,
		Found:      targetNode != nil,
	}

	if targetNode != nil {
		// Find paths from roots to the target
		paths := g.PathsTo(targetNode.PURL)
		response.Paths = internalproto.PathsToProto(paths)
		response.Dependency = targetNode.PURL
	}

	return connect.NewResponse(response), nil
}

// QueryGraph returns a filtered subset of a dependency graph.
func (h *GraphHandler) QueryGraph(
	ctx context.Context,
	req *connect.Request[graphv1.QueryGraphRequest],
) (*connect.Response[graphv1.QueryGraphResponse], error) {
	target := req.Msg.GetTarget()
	if target == "" {
		target = "."
	}

	// Security: Validate target is accessible from remote server (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTarget(target); err != nil {
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	// Build inventory options
	opts := inventory.Options{}
	if req.Msg.Options != nil {
		opts.Ecosystems = req.Msg.Options.Ecosystems
		opts.Platform = req.Msg.Options.Platform
	}

	// Collect inventory
	exec, err := h.collectInventory(ctx, target, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to collect inventory: %w", err))
	}
	if exec != nil {
		defer exec.Close()
	}

	// Build graph from inventory
	g := graph.FromInventory(exec.Result.Packages, exec.Result.Direct)
	g.UpdateDepths()

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
			if filter.MinDepth > 0 && n.Depth < int(filter.MinDepth) {
				return false
			}
			if filter.MaxDepth > 0 && n.Depth > int(filter.MaxDepth) {
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
			if filter.OnlyVulnerable && n.VulnCount.Total == 0 {
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

	// Convert to proto
	nodes, edges, _ := internalproto.GraphToProto(g)

	response := &graphv1.QueryGraphResponse{
		Target: &targetv1.Target{
			Kind:        exec.Result.Target.Kind,
			DisplayPath: exec.Result.Target.DisplayPath,
		},
		Nodes: nodes,
		Edges: edges,
		Stats: internalproto.GraphStatsToProto(g.Stats()),
	}

	return connect.NewResponse(response), nil
}
