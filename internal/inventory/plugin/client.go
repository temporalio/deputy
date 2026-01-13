// Package plugin provides a client for invoking extractor plugins.
//
// Deputy supports three types of inventory extractors:
//  1. OSV-SCALIBR extractors (built-in)
//  2. Deputy custom extractors (built-in, Go)
//  3. Plugin extractors (external, any language via pluginrpc)
//
// This package handles type 3 - invoking external plugins that implement
// the ExtractorService defined in api/deputy/plugin/v1/extractor.proto.
//
// # Architecture
//
//	┌────────────────────────────────────────────────────────────────┐
//	│                  Deputy (this package)                         │
//	│                                                                │
//	│  ┌─────────────┐   ┌──────────────────┐   ┌────────────────┐  │
//	│  │ NewClient() │──▶│ pluginrpc.Client │──▶│ ExecRunner     │  │
//	│  └─────────────┘   └──────────────────┘   │ (subprocess)   │  │
//	│                                           └───────┬────────┘  │
//	│  ┌─────────────────────────────────────────────────│────────┐ │
//	│  │ Client Methods                                  │        │ │
//	│  │  • Info()         - get metadata                │        │ │
//	│  │  • FileRequired() - check if file matches  ─────┤        │ │
//	│  │  • Extract()      - extract packages       ─────┤        │ │
//	│  └─────────────────────────────────────────────────│────────┘ │
//	└────────────────────────────────────────────────────│──────────┘
//	                                                     │
//	                                      ┌──────────────┴──────────┐
//	                                      │   stdin    │   stdout   │
//	                                      │  (proto)   │   (proto)  │
//	                                      ▼            │            │
//	┌─────────────────────────────────────│────────────│────────────┐
//	│                    Plugin Process   │            │            │
//	│                                     │            │            │
//	│  ┌──────────────────────────────────┴────────────┴─────────┐  │
//	│  │              pluginrpc.Server                           │  │
//	│  │  • --protocol flag handling                             │  │
//	│  │  • --spec flag handling                                 │  │
//	│  │  • Subcommand routing (info, file-required, extract)    │  │
//	│  └──────────────────────────┬──────────────────────────────┘  │
//	│                             │                                  │
//	│  ┌──────────────────────────▼──────────────────────────────┐  │
//	│  │              ExtractorService Handler                   │  │
//	│  │  (implemented via sdk/plugin or custom)                 │  │
//	│  └─────────────────────────────────────────────────────────┘  │
//	└────────────────────────────────────────────────────────────────┘
//
// # Plugin Discovery
//
// Plugins are discovered via:
//   - Configuration: .deputy.yaml plugins.extractors[]
//   - PATH lookup: executables matching "deputy-extractor-*"
//   - Runtime registration: client.RegisterExtractor()
//
// # Invocation Protocol
//
// Plugins are invoked as subprocesses using pluginrpc:
//   - Requests are serialized to stdin
//   - Responses come from stdout
//   - Trace context is passed via the TraceContext field
//   - Errors are returned with gRPC-style codes
//
// # Trace Context Propagation
//
//	┌─────────────────────────────────────────────────────────────┐
//	│ Deputy Process                                              │
//	│                                                             │
//	│  ctx with span ──▶ injectTraceContext() ──▶ "00-abc-def-01" │
//	│                                                    │        │
//	└────────────────────────────────────────────────────│────────┘
//	                                                     │
//	                                     TraceContext field
//	                                     in proto request
//	                                                     │
//	┌────────────────────────────────────────────────────│────────┐
//	│ Plugin Process                                     │        │
//	│                                                    ▼        │
//	│  extractTraceContext() ──▶ ctx with linked span             │
//	│                                                             │
//	└─────────────────────────────────────────────────────────────┘
//
// # Example Usage
//
//	client, err := plugin.NewClient("deputy-extractor-gemspec")
//	info, _ := client.Info(ctx)
//	required, _ := client.FileRequired(ctx, "Gemfile.lock", false, 0644, 1234)
//	if required {
//	    packages, _ := client.Extract(ctx, "Gemfile.lock", contents, "/project")
//	}
package plugin

import (
	"context"
	"fmt"
	"io"
	"os"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	pluginv1 "github.com/picatz/deputy/gen/deputy/plugin/v1"
	"github.com/picatz/deputy/gen/deputy/plugin/v1/pluginv1pluginrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"pluginrpc.com/pluginrpc"
)

const (
	// TracerName is the tracer name for plugin client spans.
	TracerName = "github.com/picatz/deputy/internal/inventory/plugin"
)

// Client wraps a pluginrpc client for the ExtractorService.
type Client struct {
	programName string
	client      pluginv1pluginrpc.ExtractorServiceClient
	info        *pluginv1.ExtractorInfo
	stderr      io.Writer
}

// ClientOption configures client behavior.
type ClientOption func(*clientOptions)

type clientOptions struct {
	stderr io.Writer
	args   []string
}

// WithStderr sets the writer for plugin stderr output.
// Useful for debugging plugins.
func WithStderr(w io.Writer) ClientOption {
	return func(o *clientOptions) {
		o.stderr = w
	}
}

// WithArgs sets additional arguments to pass to the plugin.
func WithArgs(args ...string) ClientOption {
	return func(o *clientOptions) {
		o.args = args
	}
}

// NewClient creates a new plugin client for the given program name.
// The program must be in PATH or an absolute path.
//
// The client automatically calls Info() to get extractor metadata.
func NewClient(ctx context.Context, programName string, opts ...ClientOption) (*Client, error) {
	options := &clientOptions{
		stderr: io.Discard,
	}
	for _, opt := range opts {
		opt(options)
	}

	// Create pluginrpc runner
	runnerOpts := []pluginrpc.ExecRunnerOption{}
	if len(options.args) > 0 {
		runnerOpts = append(runnerOpts, pluginrpc.ExecRunnerWithArgs(options.args...))
	}
	runner := pluginrpc.NewExecRunner(programName, runnerOpts...)

	// Create pluginrpc client
	clientOpts := []pluginrpc.ClientOption{
		pluginrpc.ClientWithStderr(options.stderr),
	}
	prpcClient := pluginrpc.NewClient(runner, clientOpts...)

	// Create service client
	serviceClient, err := pluginv1pluginrpc.NewExtractorServiceClient(prpcClient)
	if err != nil {
		return nil, fmt.Errorf("create service client: %w", err)
	}

	client := &Client{
		programName: programName,
		client:      serviceClient,
		stderr:      options.stderr,
	}

	// Get extractor info
	info, err := client.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("get extractor info from %s: %w", programName, err)
	}
	client.info = info

	return client, nil
}

// ProgramName returns the plugin program name.
func (c *Client) ProgramName() string {
	return c.programName
}

// ExtractorInfo returns the cached extractor metadata.
func (c *Client) ExtractorInfo() *pluginv1.ExtractorInfo {
	return c.info
}

// Info calls the plugin's Info RPC.
func (c *Client) Info(ctx context.Context) (*pluginv1.ExtractorInfo, error) {
	ctx, span := startSpan(ctx, "plugin.client.Info",
		attribute.String("plugin.program", c.programName),
	)
	defer span.End()

	resp, err := c.client.Info(ctx, &pluginv1.InfoRequest{})
	if err != nil {
		setSpanError(span, err)
		return nil, err
	}

	if resp.Info != nil {
		span.SetAttributes(
			attribute.String("plugin.name", resp.Info.Name),
			attribute.String("plugin.ecosystem", resp.Info.Ecosystem),
			attribute.Int("plugin.version", int(resp.Info.Version)),
		)
	}
	setSpanOK(span)
	return resp.Info, nil
}

// FileRequired calls the plugin's FileRequired RPC.
func (c *Client) FileRequired(ctx context.Context, path string, isDir bool, mode uint32, size int64) (bool, error) {
	ctx, span := startSpan(ctx, "plugin.client.FileRequired",
		attribute.String("plugin.program", c.programName),
		attribute.String("file.path", path),
		attribute.Bool("file.is_dir", isDir),
		attribute.Int64("file.size", size),
	)
	defer span.End()

	// Inject trace context
	traceContext := injectTraceContext(ctx)

	resp, err := c.client.FileRequired(ctx, &pluginv1.FileRequiredRequest{
		Path:         path,
		IsDir:        isDir,
		Mode:         mode,
		Size:         size,
		TraceContext: traceContext,
	})
	if err != nil {
		setSpanError(span, err)
		return false, err
	}

	span.SetAttributes(attribute.Bool("file.required", resp.Required))
	setSpanOK(span)
	return resp.Required, nil
}

// Extract calls the plugin's Extract RPC.
func (c *Client) Extract(ctx context.Context, path string, contents []byte, root string) ([]*pluginv1.ExtractResponse, error) {
	ctx, span := startSpan(ctx, "plugin.client.Extract",
		attribute.String("plugin.program", c.programName),
		attribute.String("file.path", path),
		attribute.Int("file.size", len(contents)),
		attribute.String("scan.root", root),
	)
	defer span.End()

	// Inject trace context
	traceContext := injectTraceContext(ctx)

	resp, err := c.client.Extract(ctx, &pluginv1.ExtractRequest{
		Path:         path,
		Contents:     contents,
		Root:         root,
		TraceContext: traceContext,
	})
	if err != nil {
		setSpanError(span, err)
		return nil, err
	}

	span.SetAttributes(attribute.Int("packages.count", len(resp.Packages)))
	setSpanOK(span)

	// Return a slice containing just this response for consistency
	return []*pluginv1.ExtractResponse{resp}, nil
}

// ExtractPackages is a convenience method that returns just the packages.
func (c *Client) ExtractPackages(ctx context.Context, path string, contents []byte, root string) ([]*Package, error) {
	ctx, span := startSpan(ctx, "plugin.client.ExtractPackages",
		attribute.String("plugin.program", c.programName),
		attribute.String("file.path", path),
		attribute.Int("file.size", len(contents)),
		attribute.String("scan.root", root),
	)
	defer span.End()

	// Inject trace context
	traceContext := injectTraceContext(ctx)

	resp, err := c.client.Extract(ctx, &pluginv1.ExtractRequest{
		Path:         path,
		Contents:     contents,
		Root:         root,
		TraceContext: traceContext,
	})
	if err != nil {
		setSpanError(span, err)
		return nil, err
	}

	span.SetAttributes(attribute.Int("packages.count", len(resp.Packages)))
	setSpanOK(span)
	return resp.Packages, nil
}

// injectTraceContext serializes the current trace context to W3C traceparent format.
func injectTraceContext(ctx context.Context) string {
	carrier := propagation.MapCarrier{}
	propagator := propagation.TraceContext{}
	propagator.Inject(ctx, carrier)
	return carrier.Get("traceparent")
}

// startSpan starts a new span for plugin client operations.
func startSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	tracer := otel.Tracer(TracerName)
	return tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// setSpanError records an error on the span.
func setSpanError(span trace.Span, err error) {
	if err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// setSpanOK marks the span as successful.
func setSpanOK(span trace.Span) {
	span.SetStatus(codes.Ok, "")
}

// Package is an alias for the dependency Package type.
type Package = dependencyv1.Package

// Discover finds extractor plugins in PATH matching the pattern "deputy-extractor-*".
func Discover() ([]string, error) {
	path := os.Getenv("PATH")
	if path == "" {
		return nil, nil
	}

	// This is a simplified implementation - in production you'd want to
	// actually search PATH directories for matching executables.
	// For now, return empty to indicate no auto-discovered plugins.
	return nil, nil
}
