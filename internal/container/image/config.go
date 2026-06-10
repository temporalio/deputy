// Package image provides container image configuration and metadata types.
//
// This package contains domain types for representing container image configuration
// (USER, ENV, ENTRYPOINT, etc.) and metadata (architecture, OS, layers) extracted
// from OCI/Docker images. These types are used for policy evaluation and security
// analysis across Deputy's scan, SBOM, and proxy commands.
//
// # Types
//
// The primary types are:
//   - [Config] - Image configuration (Dockerfile runtime settings)
//   - [Metadata] - Image metadata (architecture, size, layers)
//   - [Info] - Combined configuration, metadata, and build history
//
// # Usage
//
//	info, err := image.Extract(v1Image)
//	if err != nil {
//	    return err
//	}
//	if info.Config.IsRootUser() {
//	    // warn about running as root
//	}
//
// # Policy Integration
//
// The [Info.ToMap] method converts image data to a map suitable for CEL policy
// evaluation, providing access to fields like `image.config.is_root` and
// `image.metadata.layer_count`.
package image

import (
	"maps"
	"slices"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/temporalio/deputy/internal/policy/celconv"
	"github.com/temporalio/deputy/internal/security"
)

// Config represents the extracted configuration from a container image.
// This information is used for policy evaluation and security analysis.
type Config struct {
	// User is the user (and optionally group) to run container processes as.
	// An empty value means root, which is a security concern.
	User string `json:"user,omitempty"`

	// Env contains environment variables set in the image.
	// Sensitive values (passwords, API keys) should be detected.
	Env []string `json:"env,omitempty"`

	// Entrypoint is the command that runs when the container starts.
	Entrypoint []string `json:"entrypoint,omitempty"`

	// Cmd provides default arguments to Entrypoint.
	Cmd []string `json:"cmd,omitempty"`

	// WorkingDir is the working directory for commands.
	WorkingDir string `json:"working_dir,omitempty"`

	// ExposedPorts lists ports the container exposes.
	ExposedPorts []string `json:"exposed_ports,omitempty"`

	// Volumes lists mount points defined in the image.
	Volumes []string `json:"volumes,omitempty"`

	// Labels are key-value metadata on the image.
	Labels map[string]string `json:"labels,omitempty"`

	// Shell is the default shell for RUN commands.
	Shell []string `json:"shell,omitempty"`

	// StopSignal is the signal to stop the container.
	StopSignal string `json:"stop_signal,omitempty"`

	// Healthcheck configuration if defined.
	Healthcheck *HealthcheckConfig `json:"healthcheck,omitempty"`

	// OnBuild contains ONBUILD instructions for child images.
	OnBuild []string `json:"on_build,omitempty"`
}

// HealthcheckConfig represents container health check configuration.
type HealthcheckConfig struct {
	Test     []string      `json:"test,omitempty"`
	Interval time.Duration `json:"interval,omitempty"`
	Timeout  time.Duration `json:"timeout,omitempty"`
	Retries  int           `json:"retries,omitempty"`
}

// Metadata contains additional metadata about the image.
type Metadata struct {
	// Architecture is the CPU architecture (e.g., amd64, arm64).
	Architecture string `json:"architecture,omitempty"`

	// OS is the operating system (e.g., linux, windows).
	OS string `json:"os,omitempty"`

	// OSVersion is the OS version if specified.
	OSVersion string `json:"os_version,omitempty"`

	// Variant is the architecture variant (e.g., v8 for arm64).
	Variant string `json:"variant,omitempty"`

	// Created is when the image was created.
	Created time.Time `json:"created"`

	// Author is the image author if specified.
	Author string `json:"author,omitempty"`

	// DockerVersion is the Docker version used to build the image.
	DockerVersion string `json:"docker_version,omitempty"`

	// LayerCount is the number of layers in the image.
	LayerCount int `json:"layer_count,omitempty"`

	// Size is the total size of all layers in bytes.
	Size int64 `json:"size,omitempty"`

	// Digest is the image manifest digest.
	Digest string `json:"digest,omitempty"`
}

// Info combines configuration and metadata for policy evaluation.
type Info struct {
	Config    Config         `json:"config"`
	Metadata  Metadata       `json:"metadata"`
	History   []HistoryEntry `json:"history,omitempty"`
	BaseImage *BaseImageRef  `json:"base_image,omitempty"`
}

// BaseImageRef contains information about the base image from OCI annotations.
// This is extracted from org.opencontainers.image.base.name and
// org.opencontainers.image.base.digest annotations per the OCI Image Spec.
// See: https://github.com/opencontainers/image-spec/blob/main/annotations.md
type BaseImageRef struct {
	// Name is the base image reference (from org.opencontainers.image.base.name).
	// This should be a fully qualified reference without assumed default registry.
	Name string `json:"name,omitempty"`

	// Digest is the base image digest (from org.opencontainers.image.base.digest).
	// Format: sha256:...
	Digest string `json:"digest,omitempty"`
}

// HistoryEntry represents a single layer's history/build command.
type HistoryEntry struct {
	CreatedBy  string    `json:"created_by,omitempty"`
	Created    time.Time `json:"created"`
	Comment    string    `json:"comment,omitempty"`
	EmptyLayer bool      `json:"empty_layer,omitempty"`
}

// OCI Image Spec annotation keys for base image information.
// See: https://github.com/opencontainers/image-spec/blob/main/annotations.md
const (
	// AnnotationBaseImageName is the OCI annotation for the base image reference.
	AnnotationBaseImageName = "org.opencontainers.image.base.name"
	// AnnotationBaseImageDigest is the OCI annotation for the base image digest.
	AnnotationBaseImageDigest = "org.opencontainers.image.base.digest"
)

// Extract extracts configuration and metadata from a v1.Image.
func Extract(img v1.Image) (*Info, error) {
	if img == nil {
		return nil, nil
	}

	cf, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	if cf == nil {
		return &Info{}, nil
	}

	info := &Info{
		Config:    extractConfig(cf.Config),
		Metadata:  extractMetadata(cf, img),
		History:   extractHistory(cf.History),
		BaseImage: extractBaseImageAnnotations(img),
	}
	return info, nil
}

// extractBaseImageAnnotations extracts base image information from OCI annotations.
// This provides a no-network, no-heuristic way to identify base image layers when
// the image builder has set the standard OCI annotations.
func extractBaseImageAnnotations(img v1.Image) *BaseImageRef {
	manifest, err := img.Manifest()
	if err != nil || manifest == nil {
		return nil
	}

	// Check manifest annotations first (preferred per OCI spec)
	name := manifest.Annotations[AnnotationBaseImageName]
	digest := manifest.Annotations[AnnotationBaseImageDigest]

	// Fall back to config file labels if manifest annotations are not present.
	// Some older build tools store these in labels instead of annotations.
	if name == "" && digest == "" {
		cf, err := img.ConfigFile()
		if err == nil && cf != nil && cf.Config.Labels != nil {
			name = cf.Config.Labels[AnnotationBaseImageName]
			digest = cf.Config.Labels[AnnotationBaseImageDigest]
		}
	}

	if name == "" && digest == "" {
		return nil
	}

	return &BaseImageRef{
		Name:   name,
		Digest: digest,
	}
}

func extractConfig(cfg v1.Config) Config {
	ic := Config{
		User:       cfg.User,
		Env:        cfg.Env,
		Entrypoint: cfg.Entrypoint,
		Cmd:        cfg.Cmd,
		WorkingDir: cfg.WorkingDir,
		Labels:     cfg.Labels,
		Shell:      cfg.Shell,
		StopSignal: cfg.StopSignal,
		OnBuild:    cfg.OnBuild,
	}

	// Convert exposed ports map to sorted slice for deterministic output.
	// Map iteration order is non-deterministic in Go, so we sort to ensure
	// reproducible JSON output and consistent policy evaluation.
	if len(cfg.ExposedPorts) > 0 {
		ic.ExposedPorts = make([]string, 0, len(cfg.ExposedPorts))
		for port := range cfg.ExposedPorts {
			ic.ExposedPorts = append(ic.ExposedPorts, port)
		}
		slices.Sort(ic.ExposedPorts)
	}

	// Convert volumes map to sorted slice for deterministic output.
	if len(cfg.Volumes) > 0 {
		ic.Volumes = make([]string, 0, len(cfg.Volumes))
		for vol := range cfg.Volumes {
			ic.Volumes = append(ic.Volumes, vol)
		}
		slices.Sort(ic.Volumes)
	}

	// Extract healthcheck if present
	if cfg.Healthcheck != nil {
		ic.Healthcheck = &HealthcheckConfig{
			Test:     cfg.Healthcheck.Test,
			Interval: cfg.Healthcheck.Interval,
			Timeout:  cfg.Healthcheck.Timeout,
			Retries:  cfg.Healthcheck.Retries,
		}
	}

	return ic
}

func extractMetadata(cf *v1.ConfigFile, img v1.Image) Metadata {
	meta := Metadata{
		Architecture:  cf.Architecture,
		OS:            cf.OS,
		OSVersion:     cf.OSVersion,
		Variant:       cf.Variant,
		Author:        cf.Author,
		DockerVersion: cf.DockerVersion, //nolint:staticcheck // deprecated upstream, but the only source for this image-metadata field
	}

	if !cf.Created.Time.IsZero() {
		meta.Created = cf.Created.Time
	}

	// Get layer count and size
	if layers, err := img.Layers(); err == nil {
		meta.LayerCount = len(layers)
		for _, layer := range layers {
			if size, err := layer.Size(); err == nil {
				meta.Size += size
			}
		}
	}

	// Get digest
	if digest, err := img.Digest(); err == nil {
		meta.Digest = digest.String()
	}

	return meta
}

func extractHistory(history []v1.History) []HistoryEntry {
	if len(history) == 0 {
		return nil
	}
	entries := make([]HistoryEntry, 0, len(history))
	for _, h := range history {
		entry := HistoryEntry{
			CreatedBy:  h.CreatedBy,
			Comment:    h.Comment,
			EmptyLayer: h.EmptyLayer,
		}
		if !h.Created.Time.IsZero() {
			entry.Created = h.Created.Time
		}
		entries = append(entries, entry)
	}
	return entries
}

// IsRootUser returns true if the image runs as root (empty user or "root").
func (c *Config) IsRootUser() bool {
	user := strings.TrimSpace(c.User)
	if user == "" || user == "root" || user == "0" {
		return true
	}
	// Check for "0:0" or "root:root" formats
	if strings.HasPrefix(user, "0:") || strings.HasPrefix(user, "root:") {
		return true
	}
	return false
}

// HasSensitiveEnv returns a list of environment variable names that may contain
// sensitive information (passwords, API keys, secrets).
func (c *Config) HasSensitiveEnv() []string {
	return security.DetectSensitiveEnvFromList(c.Env)
}

// ToMap converts Info to a map for CEL policy evaluation.
// Returns an empty but properly structured map if the receiver is nil,
// ensuring CEL expressions like `has(image.config)` work consistently.
func (i *Info) ToMap() map[string]any {
	if i == nil {
		// Return empty structure so CEL can access fields without panicking.
		// CEL expressions should use has() to check for presence.
		return map[string]any{
			"config":     map[string]any{},
			"metadata":   map[string]any{},
			"history":    []any{},
			"base_image": nil,
		}
	}
	return map[string]any{
		"config":     i.configToMap(),
		"metadata":   i.metadataToMap(),
		"history":    i.historyToMaps(),
		"base_image": i.baseImageToMap(),
	}
}

func (i *Info) baseImageToMap() map[string]any {
	if i.BaseImage == nil {
		return nil
	}
	return map[string]any{
		"name":   i.BaseImage.Name,
		"digest": i.BaseImage.Digest,
	}
}

func (i *Info) configToMap() map[string]any {
	c := i.Config
	m := map[string]any{
		"user":          c.User,
		"is_root":       c.IsRootUser(),
		"env":           celconv.ToAnySlice(c.Env),
		"sensitive_env": celconv.ToAnySlice(c.HasSensitiveEnv()),
		"entrypoint":    celconv.ToAnySlice(c.Entrypoint),
		"cmd":           celconv.ToAnySlice(c.Cmd),
		"working_dir":   c.WorkingDir,
		"exposed_ports": celconv.ToAnySlice(c.ExposedPorts),
		"volumes":       celconv.ToAnySlice(c.Volumes),
		"labels":        celconv.ToAnyMap(c.Labels),
		"shell":         celconv.ToAnySlice(c.Shell),
		"stop_signal":   c.StopSignal,
		"on_build":      celconv.ToAnySlice(c.OnBuild),
	}

	if c.Healthcheck != nil {
		m["healthcheck"] = map[string]any{
			"test":     celconv.ToAnySlice(c.Healthcheck.Test),
			"interval": c.Healthcheck.Interval.String(),
			"timeout":  c.Healthcheck.Timeout.String(),
			"retries":  c.Healthcheck.Retries,
		}
	} else {
		m["healthcheck"] = nil
	}

	return m
}

func (i *Info) metadataToMap() map[string]any {
	m := i.Metadata
	result := map[string]any{
		"architecture":   m.Architecture,
		"os":             m.OS,
		"os_version":     m.OSVersion,
		"variant":        m.Variant,
		"author":         m.Author,
		"docker_version": m.DockerVersion,
		"layer_count":    m.LayerCount,
		"size":           m.Size,
		"digest":         m.Digest,
	}
	if !m.Created.IsZero() {
		result["created"] = m.Created.Unix()
	} else {
		result["created"] = int64(0)
	}
	return result
}

func (i *Info) historyToMaps() []any {
	if len(i.History) == 0 {
		return nil
	}
	result := make([]any, len(i.History))
	for idx, h := range i.History {
		entry := map[string]any{
			"created_by":  h.CreatedBy,
			"comment":     h.Comment,
			"empty_layer": h.EmptyLayer,
		}
		if !h.Created.IsZero() {
			entry["created"] = h.Created.Unix()
		} else {
			entry["created"] = int64(0)
		}
		result[idx] = entry
	}
	return result
}

// Ref represents a container image reference with provenance information.
// This is the typed representation of image registry, repository, tag, and digest.
type Ref struct {
	// Registry is the container registry hostname (e.g., "docker.io", "ghcr.io").
	Registry string `json:"registry,omitempty"`

	// Repository is the image repository path (e.g., "library/nginx", "owner/app").
	Repository string `json:"repository,omitempty"`

	// Tag is the image tag (e.g., "latest", "v1.0.0").
	Tag string `json:"tag,omitempty"`

	// Digest is the image content digest (e.g., "sha256:abc123...").
	Digest string `json:"digest,omitempty"`

	// Reference is the reference portion of the image (tag or digest).
	Reference string `json:"reference,omitempty"`

	// Image is the full image reference string (e.g., "docker.io/library/nginx:1.25").
	Image string `json:"image,omitempty"`
}

// RefFromProvenance creates an ImageRef from a provenance map (scan target provenance).
func RefFromProvenance(provenance map[string]string) *Ref {
	if len(provenance) == 0 {
		return nil
	}
	ref := &Ref{
		Registry:   provenance["registry"],
		Repository: provenance["repository"],
		Tag:        provenance["tag"],
		Digest:     provenance["digest"],
		Image:      provenance["image"],
	}
	if ref.Image == "" {
		ref.Image = provenance["image_input"]
	}
	if ref.Reference == "" {
		if ref.Digest != "" {
			ref.Reference = ref.Digest
		} else if ref.Tag != "" {
			ref.Reference = ref.Tag
		}
	}
	return ref
}

// ToMap converts Ref to a map for CEL policy evaluation.
func (r *Ref) ToMap() map[string]any {
	if r == nil {
		return map[string]any{
			"registry":   "",
			"repository": "",
			"tag":        "",
			"digest":     "",
			"reference":  "",
			"image":      "",
		}
	}
	return map[string]any{
		"registry":   r.Registry,
		"repository": r.Repository,
		"tag":        r.Tag,
		"digest":     r.Digest,
		"reference":  r.Reference,
		"image":      r.Image,
	}
}

// IsEmpty returns true if the ref has no meaningful data.
func (r *Ref) IsEmpty() bool {
	if r == nil {
		return true
	}
	return r.Registry == "" && r.Repository == "" && r.Tag == "" && r.Digest == "" && r.Image == ""
}

// String returns the full image reference string.
func (r *Ref) String() string {
	if r == nil {
		return ""
	}
	if r.Image != "" {
		return r.Image
	}
	// Build from components
	var base string
	if r.Registry != "" && r.Repository != "" {
		base = r.Registry + "/" + r.Repository
	} else if r.Repository != "" {
		base = r.Repository
	}
	if base == "" {
		return ""
	}
	if r.Digest != "" {
		return base + "@" + r.Digest
	}
	if r.Tag != "" {
		return base + ":" + r.Tag
	}
	return base
}

// PolicyPayload combines an image reference with extracted image info for policy evaluation.
// This is the complete image data structure passed to CEL policies.
type PolicyPayload struct {
	// Ref contains the image reference/provenance data.
	Ref *Ref `json:"ref,omitempty"`

	// Info contains extracted image configuration and metadata.
	Info *Info `json:"info,omitempty"`
}

// ToMap converts PolicyPayload to a map for CEL policy evaluation.
// The resulting map has the image reference fields at the top level,
// with config, metadata, and history nested inside.
func (p *PolicyPayload) ToMap() map[string]any {
	result := make(map[string]any)

	// Start with reference fields
	if p.Ref != nil {
		maps.Copy(result, p.Ref.ToMap())
	} else {
		// Provide empty defaults
		maps.Copy(result, (&Ref{}).ToMap())
	}

	// Add info fields (config, metadata, history)
	if p.Info != nil {
		infoMap := p.Info.ToMap()
		maps.Copy(result, infoMap)
	} else {
		// Provide empty defaults
		result["config"] = map[string]any{}
		result["metadata"] = map[string]any{}
		result["history"] = []any{}
	}

	return result
}
