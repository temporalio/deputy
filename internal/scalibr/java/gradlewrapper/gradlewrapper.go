package gradlewrapper

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name identifies the extractor when registered with Scalibr.
	Name                       = "java/gradlewrapper-deputy"
	gradleWrapperPropertiesRel = "gradle/wrapper/gradle-wrapper.properties"
	gradleWrapperGroupID       = "org.gradle"
	gradleWrapperArtifactID    = "gradle-wrapper"
)

var gradleVersionPattern = regexp.MustCompile(`gradle-([0-9]+(?:\.[0-9A-Za-z-]+)*)-(?:bin|all)`) // best effort

// Extractor emits a synthetic package for Gradle wrapper installations.
type Extractor struct{}

// New returns a new Gradle wrapper extractor instance.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor.
func (Extractor) Name() string { return Name }

// Version of the extractor.
func (Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired reports whether the current file is the Gradle wrapper properties file.
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.ToSlash(api.Path()) == gradleWrapperPropertiesRel
}

// Extract reads gradle-wrapper.properties and emits a Maven-style package for the wrapper.
func (Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("read gradle wrapper properties: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return inventory.Inventory{}, err
	}

	version := parseGradleWrapperVersion(data)
	if version == "" {
		version = "unknown"
	}

	metadata := &javalockfile.Metadata{ArtifactID: gradleWrapperArtifactID, GroupID: gradleWrapperGroupID}

	pkg := &extractor.Package{
		Name:      fmt.Sprintf("%s:%s", gradleWrapperGroupID, gradleWrapperArtifactID),
		Version:   version,
		PURLType:  purl.TypeMaven,
		Metadata:  metadata,
		Locations: []string{input.Path},
	}

	return inventory.Inventory{Packages: []*extractor.Package{pkg}}, nil
}

func parseGradleWrapperVersion(data []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "distributionUrl=") {
			raw := strings.TrimSpace(strings.TrimPrefix(line, "distributionUrl="))
			raw = strings.Trim(raw, "\"")
			raw = strings.ReplaceAll(raw, "\\:", ":")
			raw = strings.ReplaceAll(raw, "\\", "")
			if match := gradleVersionPattern.FindStringSubmatch(raw); len(match) == 2 {
				return match[1]
			}
			break
		}
	}
	return ""
}
