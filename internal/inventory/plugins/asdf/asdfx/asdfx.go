// Package asdfx extracts dev-toolchain dependencies from the asdf
// .tool-versions format. mise also reads .tool-versions, but the format
// originates with asdf and OSV-SCALIBR models it as a distinct ecosystem
// (runtime/asdf -> pkg:asdf) from mise.toml (runtime/mise -> pkg:mise); Deputy
// mirrors that split so inventory taxonomy stays coherent with upstream.
//
// Parsing is shared with the mise package (mise is a superset reader of the
// asdf format). This extractor emits pkg:asdf packages and, like the upstream
// runtime/asdf extractor, skips "system" and "file:"-prefixed entries that do
// not name a real version.
package asdfx

import (
	"context"
	"io"
	"log/slog"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"

	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/purlx"
)

const (
	// Name is the internal plugin identifier.
	Name = "asdf/tool-versions"
)

// Extractor implements an OSV-SCALIBR filesystem extractor for .tool-versions.
type Extractor struct{}

// New returns a new asdf extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name returns the plugin name as understood by Deputy.
func (Extractor) Name() string { return Name }

// Version returns the plugin version; Deputy uses 0 for internal plugins.
func (Extractor) Version() int { return 0 }

// Requirements declares required capabilities; asdf scanning is filesystem-only.
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired limits extraction to .tool-versions files.
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	format, ok := mise.IsConfigPath(api.Path())
	return ok && format == mise.FormatToolVersions
}

// Extract parses a .tool-versions file and returns its tool dependencies as
// pkg:asdf packages.
func (Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input == nil || input.Reader == nil {
		return inventory.Inventory{}, nil
	}
	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	cfg, err := mise.Parse(input.Path, data)
	if err != nil {
		slog.WarnContext(ctx, "tool-versions parse error", "path", input.Path, "error", err)
		return inventory.Inventory{}, nil
	}

	var pkgs []*extractor.Package
	for _, tool := range cfg.Tools {
		for _, version := range tool.Versions {
			if skipToolVersion(version) {
				continue
			}
			pkgs = append(pkgs, &extractor.Package{
				Name:      tool.Key,
				Version:   version,
				PURLType:  purlx.TypeAsdf,
				Locations: []string{input.Path},
				Metadata:  mise.MetadataFor(tool, version, cfg.Format),
			})
		}
	}
	if len(pkgs) == 0 {
		return inventory.Inventory{}, nil
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// skipToolVersion reports whether a .tool-versions entry names something other
// than an installable version, matching upstream runtime/asdf behavior.
func skipToolVersion(v string) bool {
	v = strings.TrimSpace(v)
	return v == "" || v == "system" || strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "path:") || strings.HasPrefix(v, "ref:")
}
