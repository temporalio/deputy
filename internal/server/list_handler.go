package server

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/gen/deputy/list/v1/listv1connect"
	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/otel"
	protoconv "github.com/picatz/deputy/internal/proto"
	"github.com/picatz/deputy/internal/targets"
)

// ListHandler implements the ListService gRPC handler.
type ListHandler struct {
	localMode bool
}

// Ensure ListHandler implements the ListServiceHandler interface.
var _ listv1connect.ListServiceHandler = (*ListHandler)(nil)

// ListHandlerOption configures a ListHandler.
type ListHandlerOption func(*ListHandler)

// WithListLocalMode enables local mode for ListHandler.
func WithListLocalMode() ListHandlerOption {
	return func(h *ListHandler) {
		h.localMode = true
	}
}

// NewListHandler creates a new List service handler.
func NewListHandler(opts ...ListHandlerOption) *ListHandler {
	h := &ListHandler{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// ListPackages enumerates packages in a target.
func (h *ListHandler) ListPackages(
	ctx context.Context,
	req *connect.Request[listv1.ListPackagesRequest],
) (*connect.Response[listv1.ListPackagesResponse], error) {
	// Get span from otelconnect interceptor - don't create a new one
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

	// Add business attributes to the otelconnect span
	span.SetAttributes(otel.AttrTargetPath.String(target))

	// Security: Validate target is accessible from remote server (skip in local mode)
	if !h.localMode {
		if err := targets.ValidateRemoteTarget(target); err != nil {
			otel.SetSpanError(span, err)
			return nil, connect.NewError(connect.CodeInvalidArgument, err)
		}
	}

	opts := inventory.Options{}
	if req.Msg.GetOptions() != nil {
		opts.Ecosystems = req.Msg.Options.GetEcosystems()
	}

	ref := ""
	refProvided := false
	if req.Msg.GetOptions() != nil && req.Msg.GetOptions().GetRef() != "" {
		ref = req.Msg.Options.GetRef()
		refProvided = true
	}

	exec, err := inventory.CollectRepository(ctx, target, ref, refProvided, opts)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if exec != nil {
		defer exec.Close()
	}

	// Convert packages to proto
	packages := exec.Result.Packages
	direct := exec.Result.Direct
	protoPackages := protoconv.ExtractorPackagesToProto(packages, direct)

	ecosystemCounts := make(map[string]int32)
	directCount := int32(0)
	transitiveCount := int32(0)

	for _, pkg := range packages {
		// Count by ecosystem
		eco := pkg.Ecosystem()
		if eco != "" {
			ecosystemCounts[eco]++
		}

		// Count direct vs transitive
		// Direct map contains Go module roots (e.g., "github.com/google/osv-scalibr"),
		// not PURL strings. For Go packages, use the module root for lookup.
		purl := pkg.PURL()
		isDirect := false
		if purl != nil && direct != nil {
			if purl.Type == "golang" {
				// Reconstruct module path from PURL namespace + name
				modulePath := pkg.Name
				if modulePath == "" {
					if purl.Namespace != "" {
						modulePath = purl.Namespace + "/" + purl.Name
					} else {
						modulePath = purl.Name
					}
				}
				moduleRoot := compare.GetModuleRoot(modulePath)
				isDirect = direct[moduleRoot]
			} else {
				// For non-Go ecosystems, use PURL string as key
				isDirect = direct[purl.String()]
			}
		}
		if isDirect {
			directCount++
		} else {
			transitiveCount++
		}
	}

	// Record package count on the span
	span.SetAttributes(otel.AttrPackageCount.Int(len(packages)))

	resp := &listv1.ListPackagesResponse{
		Target:   protoconv.InventoryTargetToProto(exec.Result.Target),
		Packages: protoPackages,
		Stats: &listv1.ListStats{
			TotalPackages:      int32(len(packages)),
			DirectPackages:     directCount,
			TransitivePackages: transitiveCount,
			Ecosystems:         ecosystemCounts,
		},
	}

	return connect.NewResponse(resp), nil
}

// ListEcosystems returns supported ecosystems with their file patterns.
func (h *ListHandler) ListEcosystems(
	ctx context.Context,
	req *connect.Request[listv1.ListEcosystemsRequest],
) (*connect.Response[listv1.ListEcosystemsResponse], error) {
	// Get span from otelconnect interceptor - don't create a new one
	span := otel.SpanFromContext(ctx)

	if err := protoconv.Validate(req.Msg); err != nil {
		otel.SetSpanError(span, err)
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}

	ecosystems := []*listv1.EcosystemInfo{
		{
			Name:          "go",
			DisplayName:   "Go Modules",
			Description:   "Go programming language module system",
			ManifestFiles: []string{"go.mod"},
			LockFiles:     []string{"go.sum"},
		},
		{
			Name:          "npm",
			DisplayName:   "npm",
			Description:   "Node.js package manager",
			ManifestFiles: []string{"package.json"},
			LockFiles:     []string{"package-lock.json", "npm-shrinkwrap.json"},
		},
		{
			Name:          "pypi",
			DisplayName:   "PyPI",
			Description:   "Python Package Index",
			ManifestFiles: []string{"setup.py", "pyproject.toml"},
			LockFiles:     []string{"requirements.txt", "Pipfile.lock", "poetry.lock"},
		},
		{
			Name:          "maven",
			DisplayName:   "Maven",
			Description:   "Apache Maven for Java projects",
			ManifestFiles: []string{"pom.xml"},
			LockFiles:     []string{},
		},
		{
			Name:          "cargo",
			DisplayName:   "Cargo",
			Description:   "Rust package manager",
			ManifestFiles: []string{"Cargo.toml"},
			LockFiles:     []string{"Cargo.lock"},
		},
		{
			Name:          "nuget",
			DisplayName:   "NuGet",
			Description:   ".NET package manager",
			ManifestFiles: []string{"*.csproj", "*.fsproj"},
			LockFiles:     []string{"packages.lock.json"},
		},
		{
			Name:          "rubygems",
			DisplayName:   "RubyGems",
			Description:   "Ruby package manager",
			ManifestFiles: []string{"Gemfile"},
			LockFiles:     []string{"Gemfile.lock"},
		},
	}

	return connect.NewResponse(&listv1.ListEcosystemsResponse{
		Ecosystems: ecosystems,
	}), nil
}
