package proto

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/container/image"
)

// ManifestRefsToProto converts internal ManifestRefs to proto ManifestRefs.
// Since the domain protos use pointers, we convert value slices to pointer slices.
func ManifestRefsToProto(refs []dependencyv1.ManifestRef) []*dependencyv1.ManifestRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]*dependencyv1.ManifestRef, len(refs))
	for i := range refs {
		out[i] = &dependencyv1.ManifestRef{
			Path:    refs[i].Path,
			Manager: refs[i].Manager,
			Groups:  refs[i].Groups,
		}
	}
	return out
}

// ManifestRefsFromProto converts proto ManifestRefs to internal ManifestRefs.
func ManifestRefsFromProto(refs []*dependencyv1.ManifestRef) []dependencyv1.ManifestRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]dependencyv1.ManifestRef, len(refs))
	for i, ref := range refs {
		if ref != nil {
			out[i] = dependencyv1.ManifestRef{
				Path:    ref.Path,
				Manager: ref.Manager,
				Groups:  ref.Groups,
			}
		}
	}
	return out
}

// LayerDetailsToProto returns the LayerDetails as-is since it's already a domain proto type.
// This is a pass-through for consistency with the conversion API.
func LayerDetailsToProto(ld *containerv1.LayerDetails) *containerv1.LayerDetails {
	return ld
}

// LayerDetailsFromProto returns the LayerDetails as-is since it's already a domain proto type.
func LayerDetailsFromProto(ld *containerv1.LayerDetails) *containerv1.LayerDetails {
	return ld
}

// AffectedImportsToProto converts internal AffectedImports to proto pointers.
func AffectedImportsToProto(imports []vulnerabilityv1.AffectedImport) []*vulnerabilityv1.AffectedImport {
	if len(imports) == 0 {
		return nil
	}
	out := make([]*vulnerabilityv1.AffectedImport, len(imports))
	for i := range imports {
		out[i] = &vulnerabilityv1.AffectedImport{
			Path:    imports[i].Path,
			Symbols: imports[i].Symbols,
		}
	}
	return out
}

// AffectedImportsFromProto converts proto AffectedImports to value slice.
func AffectedImportsFromProto(imports []*vulnerabilityv1.AffectedImport) []vulnerabilityv1.AffectedImport {
	if len(imports) == 0 {
		return nil
	}
	out := make([]vulnerabilityv1.AffectedImport, len(imports))
	for i, imp := range imports {
		if imp != nil {
			out[i] = vulnerabilityv1.AffectedImport{
				Path:    imp.Path,
				Symbols: imp.Symbols,
			}
		}
	}
	return out
}

// Helper functions for timestamp conversion.

func timestampOrNil(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func timeFromProto(ts *timestamppb.Timestamp) time.Time {
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// ImageInfoToScanProto converts internal image.Info to scanv1.ImageInfo.
func ImageInfoToScanProto(info *image.Info) *scanv1.ImageInfo {
	if info == nil {
		return nil
	}
	return &scanv1.ImageInfo{
		Config:   ImageConfigToScanProto(&info.Config),
		Metadata: ImageMetadataToScanProto(&info.Metadata),
		History:  HistoryEntriesToScanProto(info.History),
	}
}

// ImageInfoFromScanProto converts scanv1.ImageInfo to internal image.Info.
func ImageInfoFromScanProto(info *scanv1.ImageInfo) *image.Info {
	if info == nil {
		return nil
	}
	return &image.Info{
		Config:   ImageConfigFromScanProto(info.Config),
		Metadata: ImageMetadataFromScanProto(info.Metadata),
		History:  HistoryEntriesFromScanProto(info.History),
	}
}

// ImageConfigToScanProto converts internal image.Config to scanv1.ImageConfig.
func ImageConfigToScanProto(c *image.Config) *scanv1.ImageConfig {
	if c == nil {
		return nil
	}
	sensitiveEnv := c.HasSensitiveEnv()
	isRoot := c.IsRootUser()

	return &scanv1.ImageConfig{
		User:         c.User,
		IsRoot:       isRoot,
		Env:          c.Env,
		SensitiveEnv: sensitiveEnv,
		Entrypoint:   c.Entrypoint,
		Cmd:          c.Cmd,
		ExposedPorts: c.ExposedPorts,
		Volumes:      c.Volumes,
		Labels:       c.Labels,
		WorkingDir:   c.WorkingDir,
		Healthcheck:  HealthcheckToScanProto(c.Healthcheck),
	}
}

// ImageConfigFromScanProto converts scanv1.ImageConfig to internal image.Config.
func ImageConfigFromScanProto(c *scanv1.ImageConfig) image.Config {
	if c == nil {
		return image.Config{}
	}
	return image.Config{
		User:         c.User,
		Env:          c.Env,
		Entrypoint:   c.Entrypoint,
		Cmd:          c.Cmd,
		ExposedPorts: c.ExposedPorts,
		Volumes:      c.Volumes,
		Labels:       c.Labels,
		WorkingDir:   c.WorkingDir,
		Healthcheck:  HealthcheckFromScanProto(c.Healthcheck),
	}
}

// ImageMetadataToScanProto converts internal image.Metadata to scanv1.ImageMetadata.
func ImageMetadataToScanProto(m *image.Metadata) *scanv1.ImageMetadata {
	if m == nil {
		return nil
	}
	return &scanv1.ImageMetadata{
		Architecture: m.Architecture,
		Os:           m.OS,
		LayerCount:   int32(m.LayerCount),
		Size:         m.Size,
		Created:      timestampOrNil(m.Created),
		Digest:       m.Digest,
	}
}

// ImageMetadataFromScanProto converts scanv1.ImageMetadata to internal image.Metadata.
func ImageMetadataFromScanProto(m *scanv1.ImageMetadata) image.Metadata {
	if m == nil {
		return image.Metadata{}
	}
	return image.Metadata{
		Architecture: m.Architecture,
		OS:           m.Os,
		LayerCount:   int(m.LayerCount),
		Size:         m.Size,
		Created:      timeFromProto(m.Created),
		Digest:       m.Digest,
	}
}

// HealthcheckToScanProto converts internal HealthcheckConfig to scanv1.Healthcheck.
func HealthcheckToScanProto(h *image.HealthcheckConfig) *scanv1.Healthcheck {
	if h == nil {
		return nil
	}
	return &scanv1.Healthcheck{
		Test:     h.Test,
		Interval: h.Interval.String(),
		Timeout:  h.Timeout.String(),
		Retries:  int32(h.Retries),
	}
}

// HealthcheckFromScanProto converts scanv1.Healthcheck to internal HealthcheckConfig.
func HealthcheckFromScanProto(h *scanv1.Healthcheck) *image.HealthcheckConfig {
	if h == nil {
		return nil
	}
	interval, _ := time.ParseDuration(h.Interval)
	timeout, _ := time.ParseDuration(h.Timeout)
	return &image.HealthcheckConfig{
		Test:     h.Test,
		Interval: interval,
		Timeout:  timeout,
		Retries:  int(h.Retries),
	}
}

// HistoryEntryToScanProto converts internal HistoryEntry to scanv1.HistoryEntry.
func HistoryEntryToScanProto(h image.HistoryEntry) *scanv1.HistoryEntry {
	return &scanv1.HistoryEntry{
		CreatedBy:  h.CreatedBy,
		Created:    timestampOrNil(h.Created),
		EmptyLayer: h.EmptyLayer,
	}
}

// HistoryEntryFromScanProto converts scanv1.HistoryEntry to internal HistoryEntry.
func HistoryEntryFromScanProto(h *scanv1.HistoryEntry) image.HistoryEntry {
	if h == nil {
		return image.HistoryEntry{}
	}
	return image.HistoryEntry{
		CreatedBy:  h.CreatedBy,
		Created:    timeFromProto(h.Created),
		EmptyLayer: h.EmptyLayer,
	}
}

// HistoryEntriesToScanProto converts a slice of internal HistoryEntry to scanv1 proto.
func HistoryEntriesToScanProto(entries []image.HistoryEntry) []*scanv1.HistoryEntry {
	if len(entries) == 0 {
		return nil
	}
	out := make([]*scanv1.HistoryEntry, len(entries))
	for i, e := range entries {
		out[i] = HistoryEntryToScanProto(e)
	}
	return out
}

// HistoryEntriesFromScanProto converts a slice of scanv1 HistoryEntry to internal.
func HistoryEntriesFromScanProto(entries []*scanv1.HistoryEntry) []image.HistoryEntry {
	if len(entries) == 0 {
		return nil
	}
	out := make([]image.HistoryEntry, len(entries))
	for i, e := range entries {
		out[i] = HistoryEntryFromScanProto(e)
	}
	return out
}
