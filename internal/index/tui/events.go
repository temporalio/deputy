package tui

// Event bus definitions. Events are typed and sealed via the unexported marker.

type event interface{ isEvent() }

// FilterSubmitted indicates the user submitted a new CEL expression.
type FilterSubmitted struct{ Generation uint64; Expression string }
func (FilterSubmitted) isEvent() {}

// FilterFailed indicates the active query failed.
type FilterFailed struct{ Generation uint64; Err error }
func (FilterFailed) isEvent() {}

// LiveQueryToggled toggles live-query mode.
type LiveQueryToggled struct{ On bool }
func (LiveQueryToggled) isEvent() {}

// FacetSelected scopes results to a facet path (namespace/type/repo).
type FacetSelected struct{ Path []string }
func (FacetSelected) isEvent() {}

// FacetCleared removes any applied facet scoping.
type FacetCleared struct{}
func (FacetCleared) isEvent() {}

// ArtifactHighlighted indicates the list highlight moved.
type ArtifactHighlighted struct{ Index int }
func (ArtifactHighlighted) isEvent() {}

// ArtifactsSelected announces a selection for bulk actions.
type ArtifactsSelected struct{ Indices []int }
func (ArtifactsSelected) isEvent() {}

// TogglePane requests showing/hiding a pane (tree/detail).
type TogglePane struct{ Pane string; Show *bool }
func (TogglePane) isEvent() {}

// ResizePane requests layout resizing.
type ResizePane struct{ TreeDelta float64; StackDelta float64 }
func (ResizePane) isEvent() {}

// QueryBatch carries streamed artifacts for a generation.
type QueryBatch struct{
    Generation uint64
    Items      []artifactSummary
    Partial    bool
}
func (QueryBatch) isEvent() {}

// QueryCompleted announces completion and latency for a generation.
type QueryCompleted struct{ Generation uint64; LatencyMs int64 }
func (QueryCompleted) isEvent() {}

// DiagnosticsRequested opens the diagnostics overlay.
type DiagnosticsRequested struct{}
func (DiagnosticsRequested) isEvent() {}
