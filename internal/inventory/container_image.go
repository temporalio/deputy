package inventory

import (
	"context"
	"fmt"

	scalibr "github.com/google/osv-scalibr"
	scalibrimage "github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/plugin"
)

// ScanPackagesContainerImage scans a container image using OSV-Scalibr's image pipeline.
func ScanPackagesContainerImage(ctx context.Context, img scalibrimage.Image, opts ScanOptions) ([]*extractor.Package, error) {
	if img == nil {
		return nil, fmt.Errorf("container image is required")
	}
	cap := containerCapabilities()
	plugins, err := resolvePlugins(opts, cap)
	if err != nil {
		return nil, err
	}
	plugins = filterInventoryPlugins(plugins)

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

func containerCapabilities() *plugin.Capabilities {
	return &plugin.Capabilities{
		OS:            plugin.OSLinux,
		Network:       plugin.NetworkOffline,
		DirectFS:      false,
		RunningSystem: false,
	}
}
