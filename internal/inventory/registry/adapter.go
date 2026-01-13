// Package registry provides a thread-safe registry for extractor plugins.
package registry

import (
	"context"
	"io"
	"log/slog"

	"github.com/google/osv-scalibr/extractor"
	fsx "github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// PluginExtractor adapts a registered plugin to the SCALIBR Extractor interface.
// This allows external plugins to participate in SCALIBR scans seamlessly.
type PluginExtractor struct {
	plugin *RegisteredPlugin
}

// NewPluginExtractor creates a SCALIBR-compatible extractor for a registered plugin.
func NewPluginExtractor(p *RegisteredPlugin) *PluginExtractor {
	return &PluginExtractor{plugin: p}
}

// Name returns the plugin name.
func (e *PluginExtractor) Name() string {
	if e.plugin == nil || e.plugin.Info == nil {
		return "unknown-plugin"
	}
	return e.plugin.Info.Name
}

// Version returns the plugin version.
func (e *PluginExtractor) Version() int {
	if e.plugin == nil || e.plugin.Info == nil {
		return 0
	}
	return int(e.plugin.Info.Version)
}

// Requirements returns plugin requirements (none for external plugins).
func (e *PluginExtractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired checks if the plugin wants to process this file.
func (e *PluginExtractor) FileRequired(api fsx.FileAPI) bool {
	if e.plugin == nil || e.plugin.Client == nil {
		return false
	}

	ctx := context.Background()
	info, err := api.Stat()
	if err != nil {
		slog.Debug("plugin extractor: stat error", "plugin", e.Name(), "error", err)
		return false
	}

	required, err := e.plugin.Client.FileRequired(
		ctx,
		api.Path(),
		info.IsDir(),
		uint32(info.Mode()),
		info.Size(),
	)
	if err != nil {
		slog.Debug("plugin extractor: FileRequired error", "plugin", e.Name(), "path", api.Path(), "error", err)
		return false
	}
	return required
}

// Extract invokes the plugin to extract packages from the file.
func (e *PluginExtractor) Extract(ctx context.Context, input *fsx.ScanInput) (inventory.Inventory, error) {
	if e.plugin == nil || e.plugin.Client == nil {
		return inventory.Inventory{}, nil
	}

	// Read file contents
	contents, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	// Call plugin
	protoPackages, err := e.plugin.Client.ExtractPackages(ctx, input.Path, contents, input.Root)
	if err != nil {
		return inventory.Inventory{}, err
	}

	// Convert proto packages to SCALIBR packages
	var packages []*extractor.Package
	for _, pp := range protoPackages {
		if pp == nil {
			continue
		}

		// Determine PURL type from ecosystem
		purlType := ecosystemToPURLType(pp.Ecosystem)

		pkg := &extractor.Package{
			Name:      pp.Name,
			Version:   pp.Version,
			Locations: []string{input.Path},
			PURLType:  purlType,
		}

		packages = append(packages, pkg)
	}

	return inventory.Inventory{Packages: packages}, nil
}

// ecosystemToPURLType maps ecosystem names to PURL types.
func ecosystemToPURLType(ecosystem string) string {
	switch ecosystem {
	case "go", "golang":
		return "golang"
	case "npm", "node", "javascript":
		return "npm"
	case "pypi", "python", "pip":
		return "pypi"
	case "maven", "java":
		return "maven"
	case "rubygems", "ruby", "gem":
		return "gem"
	case "cargo", "rust", "crate":
		return "cargo"
	case "nuget", "dotnet", "csharp":
		return "nuget"
	case "hex", "elixir", "erlang":
		return "hex"
	case "pub", "dart", "flutter":
		return "pub"
	case "cocoapods", "swift", "ios":
		return "cocoapods"
	case "packagist", "php", "composer":
		return "composer"
	case "github-actions", "gha", "actions":
		return "githubactions"
	default:
		return ecosystem
	}
}

// Ensure PluginExtractor implements fsx.Extractor.
var _ fsx.Extractor = (*PluginExtractor)(nil)

// ToScalibrPlugins converts registered plugins to SCALIBR extractors.
func (r *Registry) ToScalibrPlugins() []fsx.Extractor {
	plugins := r.GetPlugins()
	extractors := make([]fsx.Extractor, 0, len(plugins))
	for _, p := range plugins {
		if p.Client != nil {
			extractors = append(extractors, NewPluginExtractor(p))
		}
	}
	return extractors
}

// ToScalibrPlugins converts registered plugins from the default registry to SCALIBR extractors.
func ToScalibrPlugins() []fsx.Extractor {
	return Default.ToScalibrPlugins()
}
