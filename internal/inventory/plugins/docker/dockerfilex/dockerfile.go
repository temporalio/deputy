// Package dockerfilex extracts container base image dependencies from Dockerfiles.
//
// It inventories:
//   - FROM instructions with image references (e.g., FROM alpine:3.19)
//   - Multi-stage build base images
//   - ARG-substituted image references
//
// The extractor is offline and performs no network fetches; base images are
// represented as packages with PURL type "docker" or "oci" for digest references.
package dockerfilex

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	"github.com/temporalio/deputy/internal/dockerfile"
)

const (
	// Name is the internal plugin identifier.
	Name = "docker/dockerfile"
)

// Extractor implements an OSV-Scalibr filesystem extractor for Dockerfile base images.
type Extractor struct{}

// New returns a new Dockerfile extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name returns the plugin name as understood by Deputy.
func (Extractor) Name() string { return Name }

// Version returns the plugin version; Deputy uses 0 for internal plugins.
func (Extractor) Version() int { return 0 }

// Requirements declares required capabilities; Dockerfile scanning is filesystem-only.
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired limits extraction to Dockerfile files.
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	return isDockerfilePath(api.Path())
}

// isDockerfilePath checks if a path looks like a Dockerfile.
func isDockerfilePath(p string) bool {
	name := filepath.Base(p)
	lower := strings.ToLower(name)

	// Exact matches (case-insensitive)
	if lower == "dockerfile" || lower == "containerfile" {
		return true
	}

	// Extension patterns: *.dockerfile, *.containerfile
	if strings.HasSuffix(lower, ".dockerfile") || strings.HasSuffix(lower, ".containerfile") {
		return true
	}

	// Suffix patterns: *Dockerfile, *Containerfile (case-sensitive for suffix)
	if strings.HasSuffix(name, "Dockerfile") || strings.HasSuffix(name, "Containerfile") {
		return true
	}

	return false
}

// Extract parses a Dockerfile and returns discovered base image dependencies.
func (Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input == nil || input.Reader == nil {
		return inventory.Inventory{}, nil
	}
	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	info, err := dockerfile.ParseBytes(data)
	if err != nil {
		// Log parse errors but don't fail - malformed Dockerfiles shouldn't block scanning
		slog.WarnContext(ctx, "dockerfile parse error",
			"path", input.Path,
			"error", err,
		)
		return inventory.Inventory{}, nil
	}
	if info == nil || len(info.Stages) == 0 {
		return inventory.Inventory{}, nil
	}

	pkgs := extractBaseImages(info, input.Path)
	if len(pkgs) == 0 {
		return inventory.Inventory{}, nil
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// extractBaseImages converts Dockerfile stages into base image packages.
func extractBaseImages(info *dockerfile.Info, dockerfilePath string) []*extractor.Package {
	if info == nil {
		return nil
	}

	var pkgs []*extractor.Package
	seen := make(map[string]bool)

	for _, stage := range info.Stages {
		// Skip scratch images (no external dependency)
		if stage.IsScratch {
			continue
		}

		// Skip references to other build stages (e.g., COPY --from=builder)
		baseImage := stage.BaseImage
		if baseImage == "" {
			continue
		}

		// Check if this is a reference to another stage name
		isStageRef := false
		for _, s := range info.Stages {
			if s.Name != "" && strings.EqualFold(s.Name, baseImage) {
				isStageRef = true
				break
			}
		}
		if isStageRef {
			continue
		}

		// Resolve ARG substitutions if possible
		resolved := baseImage
		if stage.BaseImageResolved != nil && stage.BaseImageResolved.Full != "" {
			resolved = stage.BaseImageResolved.Full
		}

		// Deduplicate by resolved image reference
		key := strings.ToLower(resolved)
		if seen[key] {
			continue
		}
		seen[key] = true

		pkg := baseImageToPackage(resolved, dockerfilePath, stage)
		if pkg != nil {
			pkgs = append(pkgs, pkg)
		}
	}

	return pkgs
}

// baseImageToPackage converts a base image reference to an extractor.Package.
// PURL type follows the convention:
// - pkg:docker for Docker Hub images (registry is docker.io or index.docker.io)
// - pkg:oci for other registries (ghcr.io, gcr.io, etc.)
func baseImageToPackage(imageRef, dockerfilePath string, stage dockerfile.Stage) *extractor.Package {
	// Use the parsed ImageRef from the stage if available for accurate tag/digest handling
	var imageName, version string
	var isDockerHub bool

	if stage.BaseImageResolved != nil && stage.BaseImageResolved.Repository != "" {
		ir := stage.BaseImageResolved
		registry := ir.Registry

		// Determine if this is Docker Hub
		isDockerHub = registry == "" || registry == "docker.io" || registry == "index.docker.io"

		// Build the full name including registry if not docker.io
		if !isDockerHub && registry != "" {
			imageName = registry + "/" + ir.Repository
		} else {
			// For docker.io, keep the repository as-is (includes library/ for official images)
			imageName = ir.Repository
		}

		// Use digest if present, otherwise tag
		if ir.Digest != "" {
			version = ir.Digest
		} else if ir.Tag != "" {
			version = ir.Tag
		} else {
			version = "latest"
		}
	} else {
		// Fallback to simple parsing
		var hasDigest bool
		imageName, version, hasDigest = splitImageRef(imageRef)
		// If using fallback parsing, guess Docker Hub for simple names
		isDockerHub = !strings.Contains(imageName, ".") || hasDigest
	}

	if imageName == "" {
		return nil
	}

	// Use pkg:docker for Docker Hub, pkg:oci for other registries
	// This aligns with Deputy's SBOM generation convention
	purlType := purl.TypeDocker
	if !isDockerHub {
		purlType = purl.TypeOCI
	}

	return &extractor.Package{
		Name:      imageName,
		Version:   version,
		PURLType:  purlType,
		Locations: []string{dockerfilePath},
		Metadata: &BaseImageMetadata{
			Raw:       imageRef,
			StageName: stage.Name,
			Platform:  stage.Platform,
			IsBuilder: stage.IsBuilderStage,
		},
	}
}

// BaseImageMetadata holds additional context about a Dockerfile base image.
type BaseImageMetadata struct {
	// Raw is the original image reference string from the Dockerfile.
	Raw string
	// StageName is the AS alias for this stage, if any.
	StageName string
	// Platform is the --platform flag value, if specified.
	Platform string
	// IsBuilder indicates if this stage is only used as a build stage.
	IsBuilder bool
}

// splitImageRef parses a container image reference into name and version/tag or digest.
// It reports hasDigest=true for @sha256:... style references.
func splitImageRef(ref string) (name, version string, hasDigest bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", "", false
	}

	// Check for digest reference (name@sha256:...)
	if idx := strings.Index(ref, "@"); idx > 0 {
		name = ref[:idx]
		version = ref[idx+1:]
		return name, version, true
	}

	// Check for tag reference (name:tag)
	// Handle cases like "docker.io/library/alpine:3.19" or "alpine:3.19"
	// Need to be careful with registry ports like "localhost:5000/image:tag"
	lastColon := strings.LastIndex(ref, ":")
	if lastColon > 0 {
		// Check if the colon is part of a port (contains / after it)
		afterColon := ref[lastColon+1:]
		if !strings.Contains(afterColon, "/") {
			name = ref[:lastColon]
			version = afterColon
			return name, version, false
		}
	}

	// No tag or digest - use "latest" as implicit version
	return ref, "latest", false
}
