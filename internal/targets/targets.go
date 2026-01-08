package targets

import (
	"context"
	"io/fs"

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
)

// Descriptor captures normalized user input (Target) alongside inferred or
// resolved provenance details (e.g., Git refs, digests, source URL) used to
// drive scanning decisions.
type Descriptor struct {
	Kind       Kind
	Target     string            // user-supplied target
	Options    map[string]string // normalized CLI options
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
	Open(ctx context.Context, target string, opts map[string]string) (Materialized, error)
}

// PriorityProvider optionally influences provider selection when multiple
// providers can detect the same target. Higher values win.
type PriorityProvider interface {
	Priority() int
}

// Registry holds a set of providers used to discover and open targets.
type Registry interface {
	Register(p Provider)
	Open(ctx context.Context, target string, opts map[string]string) (Materialized, error)
}
