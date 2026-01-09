package plugin

import (
	"context"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	pluginv1 "github.com/picatz/deputy/gen/deputy/plugin/v1"
	"github.com/picatz/deputy/gen/deputy/plugin/v1/pluginv1pluginrpc"
	"go.opentelemetry.io/otel/attribute"
	"pluginrpc.com/pluginrpc"
)

// Package is an alias for the proto Package type for convenience.
// This allows plugin authors to use plugin.Package instead of importing
// the dependency proto package directly.
type Package = dependencyv1.Package

// ExtractorInfo is an alias for the proto ExtractorInfo type.
type ExtractorInfo = pluginv1.ExtractorInfo

// Extractor is the interface that plugins must implement.
//
// The interface is designed to be simple while matching the semantics
// of OSV-SCALIBR extractors for consistency across the ecosystem.
type Extractor interface {
	// Name returns the extractor identifier.
	// Convention: "<ecosystem>/<format>" (e.g., "ruby/gemspec", "custom/myformat").
	Name() string

	// DisplayName returns a human-readable name for UI display.
	DisplayName() string

	// Ecosystem returns the package ecosystem this extractor supports.
	// Use standard ecosystem names: go, npm, pypi, maven, rubygems, cargo, etc.
	Ecosystem() string

	// Version returns the extractor version (increment on behavior changes).
	Version() int

	// Description returns context about what this extractor does.
	Description() string

	// FilePatterns returns glob patterns for files this extractor handles.
	// Examples: ["Gemfile.lock", "*.gemspec", "vendor/*/Gemfile"]
	FilePatterns() []string

	// FileRequired checks if this extractor should process a file.
	// Return true to receive an Extract call for this file.
	// This is called for every file in the scan - keep it fast (no I/O).
	//
	// Parameters:
	//   - path: File path relative to scan root
	//   - isDir: Whether the path is a directory
	//   - mode: Unix file permission mode
	//   - size: File size in bytes
	FileRequired(path string, isDir bool, mode uint32, size int64) bool

	// Extract extracts packages from a file's contents.
	// Called only for files where FileRequired returned true.
	//
	// Parameters:
	//   - path: File path relative to scan root
	//   - contents: Raw file bytes
	//   - root: Absolute path to scan root (for resolving relative paths)
	//
	// Returns a slice of discovered packages and any error.
	Extract(path string, contents []byte, root string) ([]*Package, error)
}

// Main is the entry point for extractor plugins.
// Call this from your main() function with your Extractor implementation.
//
// Example:
//
//	func main() {
//	    plugin.Main(&myExtractor{})
//	}
func Main(extractor Extractor) {
	pluginrpc.Main(func() (pluginrpc.Server, error) {
		return newServer(extractor)
	})
}

// newServer creates a pluginrpc server for the extractor.
func newServer(extractor Extractor) (pluginrpc.Server, error) {
	spec, err := pluginv1pluginrpc.ExtractorServiceSpecBuilder{
		Info: []pluginrpc.ProcedureOption{
			pluginrpc.ProcedureWithArgs("info"),
		},
		FileRequired: []pluginrpc.ProcedureOption{
			pluginrpc.ProcedureWithArgs("file-required"),
		},
		Extract: []pluginrpc.ProcedureOption{
			pluginrpc.ProcedureWithArgs("extract"),
		},
	}.Build()
	if err != nil {
		return nil, err
	}

	serverRegistrar := pluginrpc.NewServerRegistrar()
	handler := pluginrpc.NewHandler(spec)

	// Wrap the user's extractor in our handler adapter
	extractorHandler := &extractorHandlerAdapter{extractor: extractor}

	server := pluginv1pluginrpc.NewExtractorServiceServer(handler, extractorHandler)
	pluginv1pluginrpc.RegisterExtractorServiceServer(serverRegistrar, server)

	return pluginrpc.NewServer(spec, serverRegistrar)
}

// extractorHandlerAdapter adapts our Extractor interface to the generated handler.
type extractorHandlerAdapter struct {
	extractor Extractor
}

func (a *extractorHandlerAdapter) Info(ctx context.Context, req *pluginv1.InfoRequest) (*pluginv1.InfoResponse, error) {
	return &pluginv1.InfoResponse{
		Info: &pluginv1.ExtractorInfo{
			Name:         a.extractor.Name(),
			DisplayName:  a.extractor.DisplayName(),
			Ecosystem:    a.extractor.Ecosystem(),
			Version:      int32(a.extractor.Version()),
			Description:  a.extractor.Description(),
			FilePatterns: a.extractor.FilePatterns(),
		},
	}, nil
}

func (a *extractorHandlerAdapter) FileRequired(ctx context.Context, req *pluginv1.FileRequiredRequest) (*pluginv1.FileRequiredResponse, error) {
	// Extract trace context and create child span
	ctx, span := startSpan(ctx, req.TraceContext, "plugin.FileRequired",
		attribute.String("file.path", req.Path),
		attribute.Bool("file.is_dir", req.IsDir),
		attribute.Int64("file.size", req.Size),
	)
	defer span.End()

	required := a.extractor.FileRequired(req.Path, req.IsDir, req.Mode, req.Size)
	span.SetAttributes(attribute.Bool("file.required", required))
	setSpanOK(span)
	return &pluginv1.FileRequiredResponse{Required: required}, nil
}

func (a *extractorHandlerAdapter) Extract(ctx context.Context, req *pluginv1.ExtractRequest) (*pluginv1.ExtractResponse, error) {
	// Extract trace context and create child span
	ctx, span := startSpan(ctx, req.TraceContext, "plugin.Extract",
		attribute.String("file.path", req.Path),
		attribute.Int("file.size", len(req.Contents)),
		attribute.String("scan.root", req.Root),
	)
	defer span.End()

	packages, err := a.extractor.Extract(req.Path, req.Contents, req.Root)
	if err != nil {
		setSpanError(span, err)
		return nil, err
	}

	span.SetAttributes(attribute.Int("packages.count", len(packages)))
	setSpanOK(span)
	return &pluginv1.ExtractResponse{Packages: packages}, nil
}
