package inventory

import (
	"context"
	"fmt"
	"log/slog"

	scalibr "github.com/google/osv-scalibr"
	scalibrimage "github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/enricher/baseimage"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/plugin"
)

// ScanPackagesContainerImage scans a container image using OSV-Scalibr's image pipeline.
// When opts.DetectBaseImage is true, it also runs the baseimage enricher to populate
// the InBaseImage field in LayerDetails, which requires network access to query deps.dev.
func ScanPackagesContainerImage(ctx context.Context, img scalibrimage.Image, opts ScanOptions) ([]*extractor.Package, error) {
	if img == nil {
		return nil, fmt.Errorf("container image is required")
	}
	cap := containerCapabilities(opts.DetectBaseImage)
	plugins, err := resolvePlugins(opts, cap)
	if err != nil {
		return nil, err
	}
	plugins = filterInventoryPlugins(plugins)

	// Add baseimage enricher when base image detection is enabled.
	// This enricher queries deps.dev to determine if layers belong to known base images.
	if opts.DetectBaseImage {
		baseImageEnricher, err := baseimage.New(baseimage.DefaultConfig())
		if err != nil {
			slog.WarnContext(ctx, "failed to create baseimage enricher, base image detection disabled", "error", err)
		} else {
			plugins = append(plugins, baseImageEnricher)
		}
	}

	cfg := &scalibr.ScanConfig{
		Plugins:      plugins,
		Capabilities: cap,
	}

	result, err := scalibr.New().ScanContainer(ctx, img, cfg)
	if err != nil {
		return nil, err
	}
	pkgs := result.Inventory.Packages
	if scanErr := summarizeScanFailures(result); scanErr != nil {
		if len(pkgs) > 0 {
			return pkgs, scanErr
		}
		return nil, scanErr
	}
	return pkgs, nil
}

// containerCapabilities returns capabilities for container image scanning.
// When detectBaseImage is true, network access is enabled for the baseimage enricher.
func containerCapabilities(detectBaseImage bool) *plugin.Capabilities {
	network := plugin.NetworkOffline
	if detectBaseImage {
		network = plugin.NetworkOnline
	}
	return &plugin.Capabilities{
		OS:            plugin.OSLinux,
		Network:       network,
		DirectFS:      false,
		RunningSystem: false,
	}
}
