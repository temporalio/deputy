package gradlex

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// VerificationMetadataName is the extractor name for verification-metadata.xml files.
	VerificationMetadataName = "java/gradleverificationmetadata"
)

// verificationMetadataFile represents the structure of a Gradle verification-metadata.xml file.
type verificationMetadataFile struct {
	XMLName    xml.Name `xml:"verification-metadata"`
	Components struct {
		Components []verificationComponent `xml:"component"`
	} `xml:"components"`
}

// verificationComponent represents a single component in the verification metadata.
type verificationComponent struct {
	Group   string `xml:"group,attr"`
	Name    string `xml:"name,attr"`
	Version string `xml:"version,attr"`
}

// VerificationMetadataExtractor extracts Maven packages from Gradle verification-metadata.xml files.
//
// Gradle's dependency verification feature generates this XML file containing all resolved
// dependencies with their checksums. This provides a reliable source for dependency extraction
// as it contains the actual resolved versions (not ranges or variables).
//
// The file is typically located at gradle/verification-metadata.xml and is generated with:
//
//	./gradlew --write-verification-metadata sha256
type VerificationMetadataExtractor struct{}

// NewVerificationMetadataExtractor returns a new verification-metadata.xml extractor.
func NewVerificationMetadataExtractor() filesystem.Extractor {
	return &VerificationMetadataExtractor{}
}

// Name returns the extractor name.
func (e *VerificationMetadataExtractor) Name() string {
	return VerificationMetadataName
}

// Version returns the extractor version.
func (e *VerificationMetadataExtractor) Version() int {
	return 0
}

// Requirements returns the extractor's required capabilities.
func (e *VerificationMetadataExtractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file matches the verification-metadata.xml pattern.
// The file must be named "verification-metadata.xml" and located in a "gradle" directory.
func (e *VerificationMetadataExtractor) FileRequired(api filesystem.FileAPI) bool {
	p := filepath.ToSlash(api.Path())
	dir := filepath.Base(filepath.Dir(p))
	base := filepath.Base(p)
	return dir == "gradle" && base == "verification-metadata.xml"
}

// Extract parses a verification-metadata.xml file and returns discovered Maven packages.
func (e *VerificationMetadataExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input == nil || input.Reader == nil {
		return inventory.Inventory{}, nil
	}

	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("reading verification-metadata.xml: %w", err)
	}

	var metadata verificationMetadataFile
	if err := xml.Unmarshal(data, &metadata); err != nil {
		return inventory.Inventory{}, fmt.Errorf("parsing verification-metadata.xml: %w", err)
	}

	packages := make([]*extractor.Package, 0, len(metadata.Components.Components))
	seen := make(map[string]bool)

	for _, comp := range metadata.Components.Components {
		// Skip empty or invalid entries
		if comp.Group == "" || comp.Name == "" || comp.Version == "" {
			continue
		}

		// Deduplicate by coordinate
		key := fmt.Sprintf("%s:%s:%s", comp.Group, comp.Name, comp.Version)
		if seen[key] {
			continue
		}
		seen[key] = true

		pkg := &extractor.Package{
			Name:     fmt.Sprintf("%s:%s", comp.Group, comp.Name),
			Version:  comp.Version,
			PURLType: purl.TypeMaven,
			Location: extractor.LocationFromPath(input.Path),
			Metadata: &MavenMetadata{
				GroupID:    comp.Group,
				ArtifactID: comp.Name,
			},
		}
		packages = append(packages, pkg)
	}

	return inventory.Inventory{Packages: packages}, nil
}

// MavenMetadata contains Maven-specific package metadata.
type MavenMetadata struct {
	GroupID    string
	ArtifactID string
	Classifier string
	Type       string
	Scope      string
}

// IsProtoable marks MavenMetadata as OSV-SCALIBR package metadata. Deputy attaches it to
// an extractor.Package but never converts it to a proto message, so the marker
// only satisfies the upstream metadata.Protoable interface.
func (*MavenMetadata) IsProtoable() {}

// Ensure VerificationMetadataExtractor implements filesystem.Extractor.
var _ filesystem.Extractor = (*VerificationMetadataExtractor)(nil)

// ParseVerificationMetadata parses verification-metadata.xml content and returns dependencies.
// This is a utility function for use outside the extractor context.
func ParseVerificationMetadata(content []byte) ([]MavenDependency, error) {
	var metadata verificationMetadataFile
	if err := xml.Unmarshal(content, &metadata); err != nil {
		return nil, fmt.Errorf("parsing verification-metadata.xml: %w", err)
	}

	deps := make([]MavenDependency, 0, len(metadata.Components.Components))
	seen := make(map[string]bool)

	for _, comp := range metadata.Components.Components {
		if comp.Group == "" || comp.Name == "" {
			continue
		}

		key := fmt.Sprintf("%s:%s:%s", comp.Group, comp.Name, comp.Version)
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, MavenDependency{
			GroupID:    comp.Group,
			ArtifactID: comp.Name,
			Version:    comp.Version,
		})
	}

	return deps, nil
}

// MavenDependency represents a Maven dependency coordinate.
type MavenDependency struct {
	GroupID    string
	ArtifactID string
	Version    string
	Scope      string
	Classifier string
	Type       string
	Optional   bool
	Exclusions []MavenExclusion
}

// MavenExclusion represents an exclusion in a Maven dependency.
type MavenExclusion struct {
	GroupID    string
	ArtifactID string
}

// Coordinate returns the Maven coordinate string (groupId:artifactId:version).
func (d MavenDependency) Coordinate() string {
	if d.Version != "" {
		return fmt.Sprintf("%s:%s:%s", d.GroupID, d.ArtifactID, d.Version)
	}
	return fmt.Sprintf("%s:%s", d.GroupID, d.ArtifactID)
}

// Name returns the Maven name (groupId:artifactId).
func (d MavenDependency) Name() string {
	return fmt.Sprintf("%s:%s", d.GroupID, d.ArtifactID)
}

// PURL returns the Package URL for this dependency.
func (d MavenDependency) PURL() string {
	if d.Version != "" {
		return fmt.Sprintf("pkg:maven/%s/%s@%s", d.GroupID, d.ArtifactID, d.Version)
	}
	return fmt.Sprintf("pkg:maven/%s/%s", d.GroupID, d.ArtifactID)
}

// IsResolved returns true if the dependency has a concrete version (not a variable or range).
func (d MavenDependency) IsResolved() bool {
	if d.Version == "" {
		return false
	}
	// Check for unresolved property references ($var or ${var})
	if strings.Contains(d.Version, "$") {
		return false
	}
	// Check for version ranges
	if strings.ContainsAny(d.Version, "[](,)") {
		return false
	}
	// Check for dynamic versions
	if strings.HasSuffix(d.Version, "+") || d.Version == "latest.release" || d.Version == "latest.integration" {
		return false
	}
	return true
}
