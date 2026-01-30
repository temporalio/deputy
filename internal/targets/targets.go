package targets

import (
	"context"
	"io/fs"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
)

// Kind is an alias for targetv1.TargetKind.
type Kind = targetv1.TargetKind

// Kind constants - these map directly to proto enum values.
// Use these instead of the targetv1.TargetKind_* constants for cleaner code.
const (
	KindUnspecified       = targetv1.TargetKind_TARGET_KIND_UNSPECIFIED
	KindDir               = targetv1.TargetKind_TARGET_KIND_DIR
	KindFile              = targetv1.TargetKind_TARGET_KIND_FILE
	KindBinary            = targetv1.TargetKind_TARGET_KIND_BINARY
	KindGit               = targetv1.TargetKind_TARGET_KIND_GIT
	KindContainerImage    = targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE
	KindContainerInstance = targetv1.TargetKind_TARGET_KIND_CONTAINER_INSTANCE
	KindVMImage           = targetv1.TargetKind_TARGET_KIND_VM_IMAGE
	KindExtension         = targetv1.TargetKind_TARGET_KIND_EXTENSION
	KindSBOM              = targetv1.TargetKind_TARGET_KIND_SBOM
	KindPURL              = targetv1.TargetKind_TARGET_KIND_PURL
	KindDockerfile        = targetv1.TargetKind_TARGET_KIND_DOCKERFILE
	KindCloudResource     = targetv1.TargetKind_TARGET_KIND_CLOUD_RESOURCE
)

// Descriptor captures normalized user input (Target) alongside inferred or
// resolved provenance details (e.g., Git refs, digests, source URL) used to
// drive scanning decisions.
type Descriptor struct {
	Kind       Kind
	Target     string            // user-supplied target
	Options    *OpenOptions      // typed options for opening/scanning
	Provenance map[string]string // ref, digest, origin URL, etc.
}

// Materialized represents an opened target ready for scanning. Exactly one of
// FS or SBOM will typically be populated depending on the Provider kind.
type Materialized struct {
	FS      fs.FS // filesystem view for dir/file/git/container/vm
	SBOM    any   // placeholder for sbom.Document (avoid heavy dep here)
	Path    string
	Meta    Descriptor
	Data    any
	Cleanup func()
}

// Source provides detection and opening for a specific kind.
// Provider is implemented by adapters for concrete target kinds.
type Provider interface {
	Detect(ctx context.Context, target string) bool
	Open(ctx context.Context, target string, opts *OpenOptions) (Materialized, error)
}

// PriorityProvider optionally influences provider selection when multiple
// providers can detect the same target. Higher values win.
type PriorityProvider interface {
	Priority() int
}

// CloseableProvider is implemented by providers that hold resources requiring
// explicit cleanup, such as external plugin processes or network connections.
// The registry's Close method calls Close on all registered CloseableProviders.
type CloseableProvider interface {
	Provider
	// Close releases any resources held by this provider.
	// It should be safe to call Close multiple times.
	Close() error
}

// Registry holds a set of providers used to discover and open targets.
type Registry interface {
	Register(p Provider)
	Open(ctx context.Context, target string, opts *OpenOptions) (Materialized, error)
}


// ListResult contains the results of a collection List operation.
// This struct allows providers to return pagination tokens and other
// metadata alongside the discovered targets.
type ListResult struct {
	// Targets are the discovered targets for this page.
	Targets []*listv1.DiscoveredTarget

	// NextPageToken is set when more results are available.
	// Pass this value as PageToken in the next request to continue.
	// Empty string indicates this is the last page.
	NextPageToken string
}

// CollectionProvider extends Provider with collection listing support.
// Providers that can enumerate available targets (e.g., AWS AMIs in an account,
// images in a container registry) implement this interface.
//
// The URI pattern distinguishes collections from specific targets:
//   - aws://amis           → collection (list available AMIs)
//   - aws://ami/ami-xxx    → specific target (open for scanning)
//   - docker://gcr.io/p/   → collection (list images in registry path)
//   - docker://nginx:1.25  → specific target (open for scanning)
type CollectionProvider interface {
	Provider

	// IsCollection returns true if the target URI represents a collection
	// rather than a specific target. Collection URIs trigger List() instead
	// of Open().
	IsCollection(ctx context.Context, target string) bool

	// List enumerates targets within a collection. The target URI may include
	// query parameters for filtering (e.g., aws://amis?owner=self).
	// Returns a ListResult containing discovered targets and pagination info.
	// Uses the proto-defined DiscoveredTarget for CEL filtering compatibility.
	List(ctx context.Context, target string, opts *ListOptions) (*ListResult, error)
}
