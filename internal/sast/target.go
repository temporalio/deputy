package sast

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
)

// TargetKind enumerates the types of artifacts that can be analysed. The
// reachability engine is designed to keep the list open ended so new kinds of
// targets (for example SBOMs or running workloads) can hook into the same
// infrastructure without reworking call graph logic.
type TargetKind string

const (
	TargetKindRepository TargetKind = "repository"
	TargetKindContainer  TargetKind = "container"
	TargetKindArchive    TargetKind = "archive"
)

// TargetDescriptor names and classifies a target before it is materialised. It
// keeps metadata intentionally open so higher layers (CLI, API, etc.) can pass
// dial specific hints without coupling the engine to transport formats.
type TargetDescriptor struct {
	Kind     TargetKind
	Name     string
	Root     string
	Metadata map[string]any
}

// TargetSegment represents a logical slice of the target's contents. A
// repository might expose multiple segments (different language roots, vendor
// trees, generated sources) while a container could expose filesystem layers or
// build stages. Dialects may use the metadata to prioritise which segments to
// analyse.
type TargetSegment struct {
	Path        string
	FS          fs.FS
	LanguageTag string
	Metadata    map[string]any
}

// Target packages the concrete filesystem abstraction together with the
// descriptor and any pre-computed segments. Segments are optional; dialects can
// choose to rely on raw filesystem access if that is more appropriate.
type Target struct {
	Descriptor TargetDescriptor
	FS         fs.FS
	Segments   []TargetSegment
}

// TargetProvider is an optional hook that converts descriptors into concrete
// targets. The interface is small so repository, container, or runtime specific
// loaders can be registered by clients without creating import cycles.
type TargetProvider interface {
	ProvideTarget(ctx context.Context, descriptor TargetDescriptor) (*Target, error)
}

// ErrUnsupportedTarget is returned when no registered provider or dialect can
// reason about a target. It is separated from generic errors to allow CLI or API
// layers to produce actionable diagnostics.
var ErrUnsupportedTarget = errors.New("sast: unsupported target")

// ResolveTarget delegates to the provider, wrapping contextual metadata to make
// debugging easier.
func ResolveTarget(ctx context.Context, provider TargetProvider, descriptor TargetDescriptor) (*Target, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: no provider registered for %s", ErrUnsupportedTarget, descriptor.Kind)
	}
	t, err := provider.ProvideTarget(ctx, descriptor)
	if err != nil {
		return nil, fmt.Errorf("resolve target %q: %w", descriptor.Name, err)
	}
	return t, nil
}
