package scan

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/picatz/deputy/internal/container/image"
)

// Type aliases for backward compatibility.
// New code should import github.com/picatz/deputy/internal/container/image directly.
type (
	// ImageConfig represents the extracted configuration from a container image.
	// Deprecated: Use image.Config from internal/container/image instead.
	ImageConfig = image.Config

	// HealthcheckConfig represents container health check configuration.
	// Deprecated: Use image.HealthcheckConfig from internal/container/image instead.
	HealthcheckConfig = image.HealthcheckConfig

	// ImageMetadata contains additional metadata about the image.
	// Deprecated: Use image.Metadata from internal/container/image instead.
	ImageMetadata = image.Metadata

	// ImageInfo combines configuration and metadata for policy evaluation.
	// Deprecated: Use image.Info from internal/container/image instead.
	ImageInfo = image.Info

	// ImageHistoryEntry represents a single layer's history/build command.
	// Deprecated: Use image.HistoryEntry from internal/container/image instead.
	ImageHistoryEntry = image.HistoryEntry
)

// ExtractImageInfo extracts configuration and metadata from a v1.Image.
// Deprecated: Use image.Extract from internal/container/image instead.
func ExtractImageInfo(img v1.Image) (*ImageInfo, error) {
	return image.Extract(img)
}
