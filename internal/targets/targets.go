package targets

import (
	"context"
	"io/fs"
)

// Kind identifies the input type being scanned.
type Kind string

const (
	KindDir               Kind = "dir"
	KindFile              Kind = "file"
	KindBinary            Kind = "binary"
	KindGit               Kind = "git"
	KindContainerImage    Kind = "container-image"
	KindContainerInstance Kind = "container-instance"
	KindVMImage           Kind = "vm-image"
	KindExtension         Kind = "extension"
	KindSBOM              Kind = "sbom"
	KindPURL              Kind = "purl"
	KindDockerfile        Kind = "dockerfile"
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
