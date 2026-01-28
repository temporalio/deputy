// Example Deputy cloud provider plugin that uses local directories as "cloud resources".
//
// This demonstrates how to build a custom cloud provider plugin using the Deputy
// cloud plugin protocol. The plugin treats local directories as cloud resources,
// which is useful for:
//   - Testing cloud scanning workflows without real cloud access
//   - Development and debugging of cloud policies
//   - CI/CD environments without cloud credentials
//
// # Building
//
//	go build -o deputy-cloud-local ./examples/plugins/local-cloud
//
// # Usage with Deputy
//
// Place the binary in PATH or specify the full path:
//
//	# Scan a local directory as if it were a cloud resource
//	deputy scan local://ami/path/to/rootfs
//	deputy scan local://snapshot/path/to/disk-image
//
// The plugin simulates cloud metadata (region, account, tags) based on
// a .deputy-cloud.yaml file in the target directory, or uses defaults.
//
// # Example .deputy-cloud.yaml
//
//	provider: local
//	type: ami
//	region: local-1
//	account_id: "123456789012"
//	tags:
//	  Name: test-image
//	  environment: development
//
// # Testing Policies
//
// This plugin is especially useful for testing cloud policies:
//
//	# policy/cloud-test.yaml
//	entrypoint: cloud_scan_vulnerability
//	rules:
//	  - when: |
//	      resource.tags["environment"] == "production" &&
//	      vulnerability.severity == severity.CRITICAL
//	    action: deny
//	    reason: "Critical vulnerabilities in production resources require review"
//
//	# Test the policy
//	deputy scan local://ami/./testdata/production-rootfs --policy policy/cloud-test.yaml
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"connectrpc.com/connect"
	cloudv1 "github.com/picatz/deputy/gen/deputy/cloud/v1"
	"github.com/picatz/deputy/gen/deputy/cloud/v1/cloudv1connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"gopkg.in/yaml.v3"
)

func main() {
	socketPath := flag.String("socket", "", "Unix socket path for plugin communication")
	flag.Parse()

	if *socketPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: deputy-cloud-local --socket <path>")
		os.Exit(1)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	// Create the plugin server
	plugin := &localCloudPlugin{
		logger:    logger,
		resources: make(map[string]*openedResource),
	}

	// Create ConnectRPC handler
	mux := http.NewServeMux()
	mux.Handle(cloudv1connect.NewCloudProviderServiceHandler(plugin))

	// Listen on Unix socket
	_ = os.Remove(*socketPath) // Remove stale socket
	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		logger.Error("failed to listen on socket", "path", *socketPath, "error", err)
		os.Exit(1)
	}
	defer listener.Close()

	logger.Info("plugin started", "socket", *socketPath)

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

// localCloudPlugin implements CloudProviderService for local directories.
type localCloudPlugin struct {
	cloudv1connect.UnimplementedCloudProviderServiceHandler
	logger    *slog.Logger
	resources map[string]*openedResource
}

type openedResource struct {
	path     string
	metadata *resourceMetadata
}

// resourceMetadata is loaded from .deputy-cloud.yaml in the target directory.
type resourceMetadata struct {
	Provider  string            `yaml:"provider"`
	Type      string            `yaml:"type"`
	Region    string            `yaml:"region"`
	AccountID string            `yaml:"account_id"`
	Name      string            `yaml:"name"`
	Tags      map[string]string `yaml:"tags"`
}

func (p *localCloudPlugin) GetInfo(
	ctx context.Context,
	req *connect.Request[cloudv1.GetProviderInfoRequest],
) (*connect.Response[cloudv1.GetProviderInfoResponse], error) {
	return connect.NewResponse(&cloudv1.GetProviderInfoResponse{
		Name:        "local",
		DisplayName: "Local Filesystem",
		Version:     "1.0.0",
		Description: "Treats local directories as cloud resources for testing and development",
		Schemes:     []string{"local://"},
		ResourceTypes: []string{
			"ami",      // Simulated AMI (directory with rootfs)
			"snapshot", // Simulated EBS snapshot (directory)
			"disk",     // Simulated disk image (directory)
		},
		Capabilities: &cloudv1.PluginCapabilities{
			ListResources:     false,
			SmartDownload:     false,
			StreamingProgress: true,
			SecretsScanning:   true,
		},
	}), nil
}

func (p *localCloudPlugin) Detect(
	ctx context.Context,
	req *connect.Request[cloudv1.DetectRequest],
) (*connect.Response[cloudv1.DetectResponse], error) {
	target := req.Msg.GetTarget()

	// Check for local:// scheme
	if !strings.HasPrefix(target, "local://") {
		return connect.NewResponse(&cloudv1.DetectResponse{
			Detected: false,
		}), nil
	}

	// Parse: local://type/path
	rest := strings.TrimPrefix(target, "local://")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) < 2 {
		return connect.NewResponse(&cloudv1.DetectResponse{
			Detected: false,
		}), nil
	}

	resourceType := parts[0]
	resourcePath := parts[1]

	// Validate resource type
	switch resourceType {
	case "ami", "snapshot", "disk":
		// OK
	default:
		return connect.NewResponse(&cloudv1.DetectResponse{
			Detected: false,
		}), nil
	}

	return connect.NewResponse(&cloudv1.DetectResponse{
		Detected:     true,
		Scheme:       "local://",
		ResourceType: resourceType,
		ResourceId:   resourcePath,
	}), nil
}

func (p *localCloudPlugin) Open(
	ctx context.Context,
	req *connect.Request[cloudv1.OpenResourceRequest],
	stream *connect.ServerStream[cloudv1.OpenResourceEvent],
) error {
	target := req.Msg.GetTarget()
	requestID := req.Msg.GetRequestId()

	p.logger.Info("opening resource", "target", target, "request_id", requestID)

	// Parse target
	rest := strings.TrimPrefix(target, "local://")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) < 2 {
		return stream.Send(&cloudv1.OpenResourceEvent{
			RequestId: requestID,
			Details: &cloudv1.OpenResourceEvent_Error{
				Error: &cloudv1.ErrorEvent{
					Message:     "invalid target format, expected local://type/path",
					Code:        "INVALID_TARGET",
					Retriable:   false,
					Remediation: "Use format: local://ami/path/to/rootfs",
				},
			},
		})
	}

	resourceType := parts[0]
	resourcePath := parts[1]

	// Resolve path
	absPath, err := filepath.Abs(resourcePath)
	if err != nil {
		return stream.Send(&cloudv1.OpenResourceEvent{
			RequestId: requestID,
			Details: &cloudv1.OpenResourceEvent_Error{
				Error: &cloudv1.ErrorEvent{
					Message:   fmt.Sprintf("failed to resolve path: %v", err),
					Code:      "PATH_ERROR",
					Retriable: false,
				},
			},
		})
	}

	// Check path exists
	info, err := os.Stat(absPath)
	if err != nil {
		return stream.Send(&cloudv1.OpenResourceEvent{
			RequestId: requestID,
			Details: &cloudv1.OpenResourceEvent_Error{
				Error: &cloudv1.ErrorEvent{
					Message:     fmt.Sprintf("path does not exist: %v", err),
					Code:        "NOT_FOUND",
					Retriable:   false,
					Remediation: fmt.Sprintf("Create directory: mkdir -p %s", absPath),
				},
			},
		})
	}

	if !info.IsDir() {
		return stream.Send(&cloudv1.OpenResourceEvent{
			RequestId: requestID,
			Details: &cloudv1.OpenResourceEvent_Error{
				Error: &cloudv1.ErrorEvent{
					Message:     "target must be a directory",
					Code:        "INVALID_TARGET",
					Retriable:   false,
					Remediation: "Point to a directory containing the filesystem to scan",
				},
			},
		})
	}

	// Send progress
	if err := stream.Send(&cloudv1.OpenResourceEvent{
		RequestId: requestID,
		Details: &cloudv1.OpenResourceEvent_Progress{
			Progress: &cloudv1.ProgressEvent{
				Phase:   "resolving",
				Message: "Resolving local resource...",
				Percent: 25,
			},
		},
	}); err != nil {
		return err
	}

	// Load metadata from .deputy-cloud.yaml if present
	metadata := p.loadMetadata(absPath, resourceType)

	// Send progress
	if err := stream.Send(&cloudv1.OpenResourceEvent{
		RequestId: requestID,
		Details: &cloudv1.OpenResourceEvent_Progress{
			Progress: &cloudv1.ProgressEvent{
				Phase:   "ready",
				Message: "Resource ready for scanning",
				Percent: 100,
			},
		},
	}); err != nil {
		return err
	}

	// Store opened resource
	p.resources[requestID] = &openedResource{
		path:     absPath,
		metadata: metadata,
	}

	// Build tags proto
	tags := make(map[string]string)
	for k, v := range metadata.Tags {
		tags[k] = v
	}

	// Map string resource type to proto enum
	protoResourceType := stringToResourceType(resourceType)

	// Send ready event with local_path (Deputy will read directly)
	return stream.Send(&cloudv1.OpenResourceEvent{
		RequestId: requestID,
		Details: &cloudv1.OpenResourceEvent_Ready{
			Ready: &cloudv1.ReadyEvent{
				Resource: &cloudv1.CloudResource{
					Provider:     cloudv1.CloudProvider_CLOUD_PROVIDER_PLUGIN,
					ResourceType: protoResourceType,
					ResourceId:   absPath,
					Region:       metadata.Region,
					AccountId:    metadata.AccountID,
					Name:         metadata.Name,
					Tags:         tags,
					Description:  fmt.Sprintf("Local %s resource from plugin", resourceType),
				},
				LocalPath: absPath, // Deputy reads from this path directly
			},
		},
	})
}

// stringToResourceType maps string resource types to proto enum values.
// For plugin-provided types that don't map to standard types, we use UNSPECIFIED.
func stringToResourceType(t string) cloudv1.CloudResourceType {
	switch t {
	case "ami":
		return cloudv1.CloudResourceType_CLOUD_RESOURCE_TYPE_AWS_AMI
	case "snapshot":
		return cloudv1.CloudResourceType_CLOUD_RESOURCE_TYPE_AWS_EBS_SNAPSHOT
	default:
		return cloudv1.CloudResourceType_CLOUD_RESOURCE_TYPE_UNSPECIFIED
	}
}

func (p *localCloudPlugin) Close(
	ctx context.Context,
	req *connect.Request[cloudv1.CloseResourceRequest],
) (*connect.Response[cloudv1.CloseResourceResponse], error) {
	requestID := req.Msg.GetRequestId()

	p.logger.Info("closing resource", "request_id", requestID)

	delete(p.resources, requestID)

	return connect.NewResponse(&cloudv1.CloseResourceResponse{
		Success: true,
	}), nil
}

// loadMetadata loads resource metadata from .deputy-cloud.yaml or returns defaults.
func (p *localCloudPlugin) loadMetadata(path, resourceType string) *resourceMetadata {
	metadata := &resourceMetadata{
		Provider:  "local",
		Type:      resourceType,
		Region:    "local-1",
		AccountID: "000000000000",
		Name:      filepath.Base(path),
		Tags:      make(map[string]string),
	}

	// Try to load .deputy-cloud.yaml
	configPath := filepath.Join(path, ".deputy-cloud.yaml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		p.logger.Debug("no metadata file found, using defaults", "path", configPath)
		return metadata
	}

	if err := yaml.Unmarshal(data, metadata); err != nil {
		p.logger.Warn("failed to parse metadata file", "path", configPath, "error", err)
		return metadata
	}

	p.logger.Debug("loaded metadata", "path", configPath, "metadata", metadata)
	return metadata
}
