// Copyright 2025 Kent "picat" Gruber. All rights reserved.
// SPDX-License-Identifier: MIT

package proto

import (
	"github.com/google/osv-scalibr/extractor"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	inventoryv1 "github.com/picatz/deputy/gen/deputy/inventory/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	"github.com/picatz/deputy/internal/container/image"
	"github.com/picatz/deputy/internal/dockerfile"
	"github.com/picatz/deputy/internal/inventory"
)

// InventoryResultToProto converts an inventory.Result to CollectInventoryResponse.
func InventoryResultToProto(r *inventory.Result) *inventoryv1.CollectInventoryResponse {
	if r == nil {
		return nil
	}

	// Convert packages using the centralized converter
	packages := ExtractorPackagesToProto(r.Packages, r.Direct)

	// Build stats
	stats := buildInventoryStats(r.Packages, r.Direct)

	// Convert target
	target := InventoryTargetToProto(r.Target)

	// Convert image info if present
	var imageInfo *containerv1.ImageInfo
	if r.ImageInfo != nil {
		imageInfo = ImageInfoToContainerProto(r.ImageInfo)
	}

	// Convert dockerfile info if present
	var dockerfileInfo *inventoryv1.DockerfileInfo
	if r.DockerfileInfo != nil {
		dockerfileInfo = DockerfileInfoToProto(r.DockerfileInfo)
	}

	return &inventoryv1.CollectInventoryResponse{
		Target:         target,
		GeneratedAt:    timestamppb.New(r.GeneratedAt),
		Packages:       packages,
		Stats:          stats,
		ImageInfo:      imageInfo,
		DockerfileInfo: dockerfileInfo,
	}
}

// InventoryTargetToProto converts internal inventory.Target to proto Target.
func InventoryTargetToProto(t inventory.Target) *targetv1.Target {
	return &targetv1.Target{
		Kind:         targetv1.TargetKind(t.Kind),
		DisplayPath:  t.DisplayPath,
		LocalPath:    t.LocalPath,
		Ref:          t.Ref,
		EffectiveRef: t.EffectiveRef,
		CommitHash:   t.CommitHash,
		OriginUrl:    t.OriginURL,
		Cloned:       t.Cloned,
		Provenance:   t.Provenance,
	}
}

// InventoryTargetFromProto converts proto Target to internal inventory.Target.
func InventoryTargetFromProto(t *targetv1.Target) inventory.Target {
	if t == nil {
		return inventory.Target{}
	}
	return inventory.Target{
		Kind:         targetv1.TargetKind(t.Kind),
		DisplayPath:  t.DisplayPath,
		LocalPath:    t.LocalPath,
		Ref:          t.Ref,
		EffectiveRef: t.EffectiveRef,
		CommitHash:   t.CommitHash,
		OriginURL:    t.OriginUrl,
		Cloned:       t.Cloned,
		Provenance:   t.Provenance,
	}
}

// buildInventoryStats computes inventory statistics from packages.
func buildInventoryStats(pkgs []*extractor.Package, direct map[string]bool) *inventoryv1.InventoryStats {
	stats := &inventoryv1.InventoryStats{
		TotalPackages: int32(len(pkgs)),
		ByEcosystem:   make(map[string]int32),
	}

	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}

		// Count by ecosystem
		eco := pkg.Ecosystem().String()
		if eco != "" {
			stats.ByEcosystem[eco]++
		}

		// Count direct vs transitive
		purl := pkg.PURL()
		if purl != nil && direct[purl.String()] {
			stats.DirectPackages++
		} else {
			stats.TransitivePackages++
		}
	}

	return stats
}

// ImageInfoToContainerProto converts internal image.Info to container proto.
func ImageInfoToContainerProto(info *image.Info) *containerv1.ImageInfo {
	if info == nil {
		return nil
	}

	return &containerv1.ImageInfo{
		Config:   ImageConfigToContainerProto(&info.Config),
		Metadata: ImageMetadataToContainerProto(&info.Metadata),
		History:  HistoryEntriesToContainerProto(info.History),
	}
}

// ImageConfigToContainerProto converts internal image.Config to container proto.
func ImageConfigToContainerProto(c *image.Config) *containerv1.ImageConfig {
	if c == nil {
		return nil
	}

	return &containerv1.ImageConfig{
		User:         c.User,
		IsRoot:       c.IsRootUser(),
		Env:          c.Env,
		SensitiveEnv: c.HasSensitiveEnv(),
		Entrypoint:   c.Entrypoint,
		Cmd:          c.Cmd,
		ExposedPorts: c.ExposedPorts,
		Volumes:      c.Volumes,
		Labels:       c.Labels,
		WorkingDir:   c.WorkingDir,
		Healthcheck:  HealthcheckToContainerProto(c.Healthcheck),
	}
}

// ImageMetadataToContainerProto converts internal image.Metadata to container proto.
func ImageMetadataToContainerProto(m *image.Metadata) *containerv1.ImageMetadata {
	if m == nil {
		return nil
	}

	var created *timestamppb.Timestamp
	if !m.Created.IsZero() {
		created = timestamppb.New(m.Created)
	}

	return &containerv1.ImageMetadata{
		Architecture: m.Architecture,
		Os:           m.OS,
		LayerCount:   int32(m.LayerCount),
		Size:         m.Size,
		Created:      created,
		Digest:       m.Digest,
	}
}

// HealthcheckToContainerProto converts internal HealthcheckConfig to container proto.
func HealthcheckToContainerProto(h *image.HealthcheckConfig) *containerv1.HealthcheckConfig {
	if h == nil {
		return nil
	}

	return &containerv1.HealthcheckConfig{
		Test:     h.Test,
		Interval: durationpb.New(h.Interval),
		Timeout:  durationpb.New(h.Timeout),
		Retries:  int32(h.Retries),
	}
}

// HistoryEntriesToContainerProto converts internal history entries to container proto.
func HistoryEntriesToContainerProto(entries []image.HistoryEntry) []*containerv1.HistoryEntry {
	if len(entries) == 0 {
		return nil
	}

	out := make([]*containerv1.HistoryEntry, len(entries))
	for i, e := range entries {
		var created *timestamppb.Timestamp
		if !e.Created.IsZero() {
			created = timestamppb.New(e.Created)
		}
		out[i] = &containerv1.HistoryEntry{
			CreatedBy:  e.CreatedBy,
			Created:    created,
			EmptyLayer: e.EmptyLayer,
		}
	}
	return out
}

// DockerfileInfoToProto converts internal dockerfile.Info to proto.
func DockerfileInfoToProto(info *dockerfile.Info) *inventoryv1.DockerfileInfo {
	return DockerfileInfoWithAnalysisToProto(info, nil)
}

// DockerfileInfoWithAnalysisToProto converts internal dockerfile.Info and Analysis to proto.
func DockerfileInfoWithAnalysisToProto(info *dockerfile.Info, analysis *dockerfile.Analysis) *inventoryv1.DockerfileInfo {
	if info == nil {
		return nil
	}

	stages := make([]*inventoryv1.DockerfileStage, len(info.Stages))
	for i, s := range info.Stages {
		stages[i] = DockerfileStageToProto(&s)
	}

	var finalStage *inventoryv1.DockerfileStage
	if info.FinalStage != nil {
		finalStage = DockerfileStageToProto(info.FinalStage)
	}

	return &inventoryv1.DockerfileInfo{
		Path:       info.Path,
		Stages:     stages,
		FinalStage: finalStage,
		Args:       info.Args,
		Analysis:   DockerfileAnalysisToProto(analysis),
	}
}

// DockerfileStageToProto converts internal dockerfile.Stage to proto.
func DockerfileStageToProto(s *dockerfile.Stage) *inventoryv1.DockerfileStage {
	if s == nil {
		return nil
	}

	var baseImageResolved *inventoryv1.ImageReference
	if s.BaseImageResolved != nil {
		baseImageResolved = &inventoryv1.ImageReference{
			Registry:   s.BaseImageResolved.Registry,
			Repository: s.BaseImageResolved.Repository,
			Tag:        s.BaseImageResolved.Tag,
			Digest:     s.BaseImageResolved.Digest,
		}
	}

	return &inventoryv1.DockerfileStage{
		Index:             int32(s.Index),
		Name:              s.Name,
		BaseImage:         s.BaseImage,
		BaseImageResolved: baseImageResolved,
		Platform:          s.Platform,
		IsScratch:         s.IsScratch,
		IsBuilderStage:    s.IsBuilderStage,
		User:              s.User,
		IsRoot:            s.IsRoot(),
		Workdir:           s.Workdir,
		EnvVars:           s.EnvVars,
		SensitiveEnv:      s.HasSensitiveEnv(),
		ExposedPorts:      s.ExposedPorts,
		Labels:            s.Labels,
	}
}

// DockerfileAnalysisToProto converts internal dockerfile.Analysis to proto.
func DockerfileAnalysisToProto(a *dockerfile.Analysis) *inventoryv1.DockerfileAnalysis {
	if a == nil {
		return nil
	}

	return &inventoryv1.DockerfileAnalysis{
		StageCount:          int32(a.StageCount),
		HasMultiStage:       a.HasMultiStage,
		BuilderStageCount:   int32(a.BuilderStageCount),
		FinalStageIsRoot:    a.FinalStageIsRoot,
		FinalStageIsScratch: a.FinalStageIsScratch,
		SensitiveEnvVars:    a.SensitiveEnvVars,
		HasAddUrl:           a.HasAddURL,
	}
}

// DockerfileInfoFromProto converts proto DockerfileInfo to internal dockerfile.Info.
func DockerfileInfoFromProto(info *inventoryv1.DockerfileInfo) *dockerfile.Info {
	if info == nil {
		return nil
	}

	stages := make([]dockerfile.Stage, len(info.Stages))
	for i, s := range info.Stages {
		stages[i] = *DockerfileStageFromProto(s)
	}

	return &dockerfile.Info{
		Path:       info.Path,
		Stages:     stages,
		FinalStage: DockerfileStageFromProto(info.FinalStage),
		Args:       info.Args,
	}
}

// DockerfileStageFromProto converts proto DockerfileStage to internal dockerfile.Stage.
func DockerfileStageFromProto(s *inventoryv1.DockerfileStage) *dockerfile.Stage {
	if s == nil {
		return nil
	}

	var baseImageResolved *dockerfile.ImageRef
	if s.BaseImageResolved != nil {
		baseImageResolved = &dockerfile.ImageRef{
			Registry:   s.BaseImageResolved.Registry,
			Repository: s.BaseImageResolved.Repository,
			Tag:        s.BaseImageResolved.Tag,
			Digest:     s.BaseImageResolved.Digest,
		}
	}

	return &dockerfile.Stage{
		Index:             int(s.Index),
		Name:              s.Name,
		BaseImage:         s.BaseImage,
		BaseImageResolved: baseImageResolved,
		Platform:          s.Platform,
		IsScratch:         s.IsScratch,
		IsBuilderStage:    s.IsBuilderStage,
		User:              s.User,
		Workdir:           s.Workdir,
		EnvVars:           s.EnvVars,
		ExposedPorts:      s.ExposedPorts,
		Labels:            s.Labels,
	}
}

// DockerfileAnalysisFromProtoNested extracts analysis from nested DockerfileInfo proto.
func DockerfileAnalysisFromProtoNested(info *inventoryv1.DockerfileInfo) *dockerfile.Analysis {
	if info == nil || info.Analysis == nil {
		return nil
	}
	return DockerfileAnalysisFromProto(info.Analysis)
}

// DockerfileAnalysisFromProto converts proto DockerfileAnalysis to internal dockerfile.Analysis.
func DockerfileAnalysisFromProto(a *inventoryv1.DockerfileAnalysis) *dockerfile.Analysis {
	if a == nil {
		return nil
	}
	return &dockerfile.Analysis{
		StageCount:          int(a.StageCount),
		HasMultiStage:       a.HasMultiStage,
		BuilderStageCount:   int(a.BuilderStageCount),
		FinalStageIsRoot:    a.FinalStageIsRoot,
		FinalStageIsScratch: a.FinalStageIsScratch,
		SensitiveEnvVars:    a.SensitiveEnvVars,
		HasAddURL:           a.HasAddUrl,
	}
}

// ImageInfoToProto is an alias for ImageInfoToContainerProto for convenience.
func ImageInfoToProto(info *image.Info) *containerv1.ImageInfo {
	return ImageInfoToContainerProto(info)
}
