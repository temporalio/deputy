// Package cloudplugin provides SDK helpers for building Deputy cloud provider plugins.
//
// Cloud provider plugins enable Deputy to scan resources from custom cloud platforms
// (OpenStack, vSphere, MinIO, etc.) without modifying Deputy's core.
//
// # Architecture
//
// Plugins are standalone executables that communicate with Deputy via ConnectRPC
// over Unix sockets. Deputy discovers plugins named `deputy-cloud-<name>` in PATH
// and launches them on demand.
//
//	┌─────────────┐         Unix Socket         ┌─────────────────────┐
//	│   Deputy    │◄────── ConnectRPC ─────────►│ deputy-cloud-<name> │
//	│   (scan)    │                             │     (your code)     │
//	└─────────────┘                             └─────────────────────┘
//	      │                                               │
//	      │ 1. GetInfo() - Plugin metadata                │
//	      │ 2. Detect() - Can you handle this target?     │
//	      │ 3. Open() - Materialize the resource          │
//	      │ 4. Close() - Release resources                │
//	      └───────────────────────────────────────────────┘
//
// # Quick Start
//
// Create a cloud provider plugin in a single main.go:
//
//	package main
//
//	import (
//	    "context"
//	    "github.com/picatz/deputy/sdk/cloudplugin"
//	)
//
//	func main() {
//	    cloudplugin.Main(&myCloudProvider{})
//	}
//
//	type myCloudProvider struct{}
//
//	func (p *myCloudProvider) Info() cloudplugin.ProviderInfo {
//	    return cloudplugin.ProviderInfo{
//	        Name:          "mycloud",
//	        DisplayName:   "My Cloud Platform",
//	        Version:       "1.0.0",
//	        Description:   "Scans resources from My Cloud Platform",
//	        Schemes:       []string{"mycloud://"},
//	        ResourceTypes: []string{"instance", "volume", "image"},
//	    }
//	}
//
//	func (p *myCloudProvider) Detect(ctx context.Context, target string) (*cloudplugin.DetectResult, error) {
//	    if !strings.HasPrefix(target, "mycloud://") {
//	        return &cloudplugin.DetectResult{Detected: false}, nil
//	    }
//	    // Parse and validate target...
//	    return &cloudplugin.DetectResult{
//	        Detected:     true,
//	        Scheme:       "mycloud://",
//	        ResourceType: "instance",
//	        ResourceID:   "i-12345",
//	    }, nil
//	}
//
//	func (p *myCloudProvider) Open(ctx context.Context, req cloudplugin.OpenRequest) cloudplugin.OpenStream {
//	    return func(yield func(cloudplugin.OpenEvent) bool) {
//	        // Send progress updates...
//	        yield(cloudplugin.ProgressEvent{Phase: "downloading", Percent: 50})
//
//	        // Materialize the resource to a local path...
//	        localPath := materializeResource(req.Target)
//
//	        // Send ready event with local path
//	        yield(cloudplugin.ReadyEvent{
//	            Resource: cloudplugin.ResourceInfo{
//	                Provider:   "mycloud",
//	                Type:       "instance",
//	                ID:         "i-12345",
//	                Region:     "us-east-1",
//	                Tags:       map[string]string{"env": "prod"},
//	            },
//	            LocalPath: localPath,
//	        })
//	    }
//	}
//
//	func (p *myCloudProvider) Close(ctx context.Context, requestID string) error {
//	    // Cleanup resources...
//	    return nil
//	}
//
// # Building and Installing
//
//	go build -o deputy-cloud-mycloud .
//	mv deputy-cloud-mycloud /usr/local/bin/
//
// # Usage with Deputy
//
//	deputy scan mycloud://instance/i-12345
//	deputy scan mycloud://volume/vol-abc123 --region us-west-2
//
// # Resource Materialization
//
// Plugins materialize cloud resources in one of two ways:
//
//  1. LocalPath: Download/mount resource to a local directory. Deputy reads from
//     this path directly. This is the simplest approach.
//
//  2. FsSocket: Serve an fs.FS-compatible interface over a Unix socket. This
//     enables streaming access without full materialization. Advanced use only.
//
// For most plugins, use LocalPath:
//
//	yield(cloudplugin.ReadyEvent{
//	    LocalPath: "/tmp/deputy-cloud-xxx/rootfs",
//	})
//
// # Metadata and Tags
//
// Cloud resource metadata is used for policy evaluation. Provide accurate
// information to enable policies like:
//
//	# Block scanning production resources with critical vulns
//	when: resource.tags["environment"] == "production"
//
// Key metadata fields:
//   - Provider: Cloud platform name ("aws", "azure", "gcp", or your plugin name)
//   - Type: Resource type ("ami", "instance", "volume", etc.)
//   - ID: Provider-specific resource identifier
//   - Region: Cloud region
//   - AccountID: Account/subscription/project identifier
//   - Tags: Resource tags/labels (used heavily in policies)
//
// # Progress Reporting
//
// For long-running operations (downloads, mounts), report progress:
//
//	yield(cloudplugin.ProgressEvent{
//	    Phase:            "downloading",
//	    Message:          "Downloading disk image...",
//	    Percent:          45,
//	    BytesTransferred: 1024 * 1024 * 500,  // 500MB
//	    BytesTotal:       1024 * 1024 * 1000, // 1GB
//	})
//
// # Error Handling
//
// Return structured errors with remediation hints:
//
//	yield(cloudplugin.ErrorEvent{
//	    Message:     "authentication failed",
//	    Code:        "AUTH_FAILED",
//	    Retriable:   false,
//	    Remediation: "Run 'mycloud auth login' to authenticate",
//	})
//
// # Testing
//
// Test your plugin without Deputy:
//
//	# Get plugin info
//	./deputy-cloud-mycloud --socket /tmp/test.sock &
//	grpcurl -unix /tmp/test.sock deputy.cloud.v1.CloudProviderService/GetInfo
//
// Or use the SDK test helpers:
//
//	func TestMyProvider(t *testing.T) {
//	    p := &myCloudProvider{}
//	    info := p.Info()
//	    assert.Equal(t, "mycloud", info.Name)
//	}
//
// # Security Considerations
//
//  1. Never handle credentials directly. Use platform SDK credential chains:
//     - OpenStack: OS_AUTH_URL, clouds.yaml
//     - vSphere: VSPHERE_USER, VSPHERE_PASSWORD
//     - Custom: Delegate to your platform's standard auth
//
//  2. Clean up temporary files. Use the cleanup callback or defer.
//
//  3. Validate targets. Don't allow path traversal or arbitrary file access.
//
// # Reference
//
// See the local-cloud example for a complete working plugin:
//
//	examples/plugins/local-cloud/main.go
//
// Proto definitions:
//
//	api/deputy/cloud/v1/plugin.proto
package cloudplugin
