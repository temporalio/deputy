package cloud

import (
	"context"
	"errors"
	"io"
	"io/fs"
)

// Provider identifies a cloud provider.
type Provider string

// Cloud provider constants.
const (
	ProviderAWS    Provider = "aws"
	ProviderAzure  Provider = "azure"
	ProviderGCP    Provider = "gcp"
	ProviderPlugin Provider = "plugin"
)

// ResourceType identifies a type of cloud resource.
type ResourceType string

// AWS resource types.
const (
	ResourceTypeAWSAMI         ResourceType = "ami"
	ResourceTypeAWSEBSSnapshot ResourceType = "ebs-snapshot"
	ResourceTypeAWSLambda      ResourceType = "lambda"
	ResourceTypeAWSECRImage    ResourceType = "ecr-image"
)

// Azure resource types.
const (
	ResourceTypeAzureVMImage  ResourceType = "azure-vm-image"
	ResourceTypeAzureDisk     ResourceType = "azure-disk"
	ResourceTypeAzureACRImage ResourceType = "acr-image"
	ResourceTypeAzureFunction ResourceType = "azure-function"
)

// GCP resource types.
const (
	ResourceTypeGCPImage    ResourceType = "gcp-image"
	ResourceTypeGCPDisk     ResourceType = "gcp-disk"
	ResourceTypeGCPGARImage ResourceType = "gar-image"
	ResourceTypeGCPFunction ResourceType = "gcp-function"
)

// Resource represents a scannable cloud resource.
// Implementations provide access to resource metadata and filesystem content.
type Resource interface {
	// Provider returns the cloud provider (aws, azure, gcp, plugin).
	Provider() Provider

	// Type returns the resource type (ami, ebs-snapshot, lambda, etc.).
	Type() ResourceType

	// ID returns the provider-specific resource identifier.
	ID() string

	// Region returns the cloud region.
	Region() string

	// AccountID returns the account/subscription/project identifier.
	AccountID() string

	// Tags returns resource tags/labels.
	Tags() map[string]string

	// Name returns a human-readable name (may be empty).
	Name() string

	// FS returns a filesystem view of the resource for scanning.
	// This may trigger downloading or mounting the resource.
	FS(ctx context.Context) (fs.FS, error)

	// Close releases any resources (temp files, connections, etc.).
	Close() error
}

// BlockReader provides block-level read access to cloud storage.
// This is used for smart downloading (e.g., EBS Direct API).
type BlockReader interface {
	io.ReaderAt
	io.Closer

	// Size returns the total size in bytes.
	Size() int64

	// BlockSize returns the block size used by the underlying storage.
	// Returns 0 if block-level access is not available.
	BlockSize() int64
}

// Common errors.
var (
	// ErrUnsupportedTarget is returned when no provider handles the target URI.
	ErrUnsupportedTarget = errors.New("unsupported cloud target")

	// ErrAuthenticationFailed is returned when cloud authentication fails.
	ErrAuthenticationFailed = errors.New("cloud authentication failed")

	// ErrResourceNotFound is returned when the cloud resource doesn't exist.
	ErrResourceNotFound = errors.New("cloud resource not found")

	// ErrAccessDenied is returned when access to the resource is denied.
	ErrAccessDenied = errors.New("access denied to cloud resource")

	// ErrRegionRequired is returned when a region is required but not provided.
	ErrRegionRequired = errors.New("region required for cloud resource")

	// ErrInvalidTarget is returned when the target URI is malformed.
	ErrInvalidTarget = errors.New("invalid cloud target URI")
)
