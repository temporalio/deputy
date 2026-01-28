package cloudplugin

import (
	"context"
	"flag"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"connectrpc.com/connect"
	cloudv1 "github.com/picatz/deputy/gen/deputy/cloud/v1"
	"github.com/picatz/deputy/gen/deputy/cloud/v1/cloudv1connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// Provider is the interface that cloud provider plugins must implement.
type Provider interface {
	// Info returns plugin metadata.
	Info() ProviderInfo

	// Detect checks if the target URI is handled by this provider.
	Detect(ctx context.Context, target string) (*DetectResult, error)

	// Open materializes a cloud resource for scanning.
	// Returns an iterator that yields progress updates and a final ready/error event.
	Open(ctx context.Context, req OpenRequest) iter.Seq[OpenEvent]

	// Close releases resources from a previous Open call.
	Close(ctx context.Context, requestID string) error
}

// ProviderInfo describes a cloud provider plugin.
type ProviderInfo struct {
	// Name is the plugin identifier (matches deputy-cloud-<name>).
	Name string

	// DisplayName is a human-readable name.
	DisplayName string

	// Version is the plugin version.
	Version string

	// Description explains what this plugin does.
	Description string

	// Schemes lists URI schemes handled (e.g., "openstack://", "vsphere://").
	Schemes []string

	// ResourceTypes lists supported resource types.
	ResourceTypes []string

	// Capabilities describes what the plugin can do.
	Capabilities Capabilities
}

// Capabilities describes what a cloud provider plugin can do.
type Capabilities struct {
	// ListResources indicates the plugin can list available resources.
	ListResources bool

	// SmartDownload indicates the plugin supports downloading only needed blocks.
	SmartDownload bool

	// StreamingProgress indicates the plugin reports progress during Open.
	StreamingProgress bool

	// SecretsScanning indicates the plugin supports secrets detection.
	SecretsScanning bool
}

// DetectResult indicates whether the plugin handles a target.
type DetectResult struct {
	// Detected is true if this plugin handles the target.
	Detected bool

	// Scheme is the matched URI scheme.
	Scheme string

	// ResourceType is the detected resource type.
	ResourceType string

	// ResourceID is the parsed resource identifier.
	ResourceID string
}

// OpenRequest contains the request to open a cloud resource.
type OpenRequest struct {
	// Target is the URI to open.
	Target string

	// OpenOptions contains structured options for opening.
	// Plugin authors should prefer these typed fields over the legacy Options map.
	OpenOptions *cloudv1.OpenOptions

	// RequestID is a unique identifier for this request (for correlation).
	RequestID string
}

// OpenEvent is yielded during the Open operation.
type OpenEvent interface {
	openEvent()
}

// ProgressEvent reports progress during resource opening.
type ProgressEvent struct {
	// Phase describes the current phase (e.g., "downloading", "mounting").
	Phase string

	// Message is a human-readable progress message.
	Message string

	// Percent is the progress percentage (0-100, -1 if unknown).
	Percent int

	// BytesTransferred is the number of bytes transferred so far.
	BytesTransferred int64

	// BytesTotal is the total bytes (-1 if unknown).
	BytesTotal int64
}

func (ProgressEvent) openEvent() {}

// ReadyEvent indicates the resource is ready for scanning.
type ReadyEvent struct {
	// Resource contains metadata about the opened resource.
	Resource ResourceInfo

	// LocalPath is where the resource was materialized.
	// Deputy reads from this path directly.
	LocalPath string

	// FsSocket is a Unix socket path serving an fs.FS interface.
	// Use this for streaming access without full materialization.
	// If LocalPath is set, this is ignored.
	FsSocket string
}

func (ReadyEvent) openEvent() {}

// ErrorEvent reports an error during resource opening.
type ErrorEvent struct {
	// Message describes the error.
	Message string

	// Code is a machine-readable error code.
	Code string

	// Retriable indicates if the operation can be retried.
	Retriable bool

	// Remediation suggests how to fix the error.
	Remediation string
}

func (ErrorEvent) openEvent() {}

// ResourceInfo contains metadata about a cloud resource.
type ResourceInfo struct {
	// Provider is the cloud provider name.
	Provider string

	// Type is the resource type (e.g., "ami", "instance", "volume").
	Type string

	// ID is the provider-specific resource identifier.
	ID string

	// Region is the cloud region.
	Region string

	// AccountID is the account/subscription/project identifier.
	AccountID string

	// Name is a human-readable name (optional).
	Name string

	// Description is a resource description (optional).
	Description string

	// Tags are resource tags/labels.
	Tags map[string]string
}

// Main is the entrypoint for cloud provider plugins.
// Call this from your main() function with your Provider implementation.
func Main(p Provider) {
	socketPath := flag.String("socket", "", "Unix socket path for plugin communication")
	flag.Parse()

	if *socketPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: deputy-cloud-<name> --socket <path>")
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create the adapter
	adapter := &providerAdapter{
		provider: p,
		logger:   logger,
	}

	// Create ConnectRPC handler
	mux := http.NewServeMux()
	mux.Handle(cloudv1connect.NewCloudProviderServiceHandler(adapter))

	// Listen on Unix socket
	_ = os.Remove(*socketPath) // Remove stale socket
	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		logger.Error("failed to listen on socket", "path", *socketPath, "error", err)
		os.Exit(1)
	}
	defer listener.Close()

	info := p.Info()
	logger.Info("cloud provider plugin started",
		"name", info.Name,
		"version", info.Version,
		"socket", *socketPath,
	)

	// Handle shutdown gracefully
	server := &http.Server{
		Handler: h2c.NewHandler(mux, &http2.Server{}),
	}

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		logger.Info("shutting down")
		server.Close()
	}()

	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}

// providerAdapter adapts a Provider to the ConnectRPC interface.
type providerAdapter struct {
	cloudv1connect.UnimplementedCloudProviderServiceHandler
	provider Provider
	logger   *slog.Logger
}

func (a *providerAdapter) GetInfo(
	ctx context.Context,
	req *connect.Request[cloudv1.GetProviderInfoRequest],
) (*connect.Response[cloudv1.GetProviderInfoResponse], error) {
	info := a.provider.Info()

	return connect.NewResponse(&cloudv1.GetProviderInfoResponse{
		Name:          info.Name,
		DisplayName:   info.DisplayName,
		Version:       info.Version,
		Description:   info.Description,
		Schemes:       info.Schemes,
		ResourceTypes: info.ResourceTypes,
		Capabilities: &cloudv1.PluginCapabilities{
			ListResources:     info.Capabilities.ListResources,
			SmartDownload:     info.Capabilities.SmartDownload,
			StreamingProgress: info.Capabilities.StreamingProgress,
			SecretsScanning:   info.Capabilities.SecretsScanning,
		},
	}), nil
}

func (a *providerAdapter) Detect(
	ctx context.Context,
	req *connect.Request[cloudv1.DetectRequest],
) (*connect.Response[cloudv1.DetectResponse], error) {
	result, err := a.provider.Detect(ctx, req.Msg.GetTarget())
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&cloudv1.DetectResponse{
		Detected:     result.Detected,
		Scheme:       result.Scheme,
		ResourceType: result.ResourceType,
		ResourceId:   result.ResourceID,
	}), nil
}

func (a *providerAdapter) Open(
	ctx context.Context,
	req *connect.Request[cloudv1.OpenResourceRequest],
	stream *connect.ServerStream[cloudv1.OpenResourceEvent],
) error {
	openReq := OpenRequest{
		Target:      req.Msg.GetTarget(),
		OpenOptions: req.Msg.GetOpenOptions(),
		RequestID:   req.Msg.GetRequestId(),
	}

	for event := range a.provider.Open(ctx, openReq) {
		protoEvent := &cloudv1.OpenResourceEvent{
			RequestId: openReq.RequestID,
		}

		switch e := event.(type) {
		case ProgressEvent:
			protoEvent.Details = &cloudv1.OpenResourceEvent_Progress{
				Progress: &cloudv1.ProgressEvent{
					Phase:            e.Phase,
					Message:          e.Message,
					Percent:          int32(e.Percent),
					BytesTransferred: e.BytesTransferred,
					BytesTotal:       e.BytesTotal,
				},
			}
		case ReadyEvent:
			protoEvent.Details = &cloudv1.OpenResourceEvent_Ready{
				Ready: &cloudv1.ReadyEvent{
					Resource: &cloudv1.CloudResource{
						Provider:    cloudv1.CloudProvider_CLOUD_PROVIDER_PLUGIN,
						ResourceId:  e.Resource.ID,
						Region:      e.Resource.Region,
						AccountId:   e.Resource.AccountID,
						Name:        e.Resource.Name,
						Description: e.Resource.Description,
						Tags:        e.Resource.Tags,
					},
					LocalPath: e.LocalPath,
					FsSocket:  e.FsSocket,
				},
			}
		case ErrorEvent:
			protoEvent.Details = &cloudv1.OpenResourceEvent_Error{
				Error: &cloudv1.ErrorEvent{
					Message:     e.Message,
					Code:        e.Code,
					Retriable:   e.Retriable,
					Remediation: e.Remediation,
				},
			}
		}

		if err := stream.Send(protoEvent); err != nil {
			return err
		}
	}

	return nil
}

func (a *providerAdapter) Close(
	ctx context.Context,
	req *connect.Request[cloudv1.CloseResourceRequest],
) (*connect.Response[cloudv1.CloseResourceResponse], error) {
	err := a.provider.Close(ctx, req.Msg.GetRequestId())
	if err != nil {
		return connect.NewResponse(&cloudv1.CloseResourceResponse{
			Success: false,
			Error:   err.Error(),
		}), nil
	}

	return connect.NewResponse(&cloudv1.CloseResourceResponse{
		Success: true,
	}), nil
}
