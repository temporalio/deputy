package inventory

import (
	"context"
	"fmt"
	"log/slog"

	scalibr "github.com/google/osv-scalibr"
	scalibrimage "github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/enricher/baseimage"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
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

// ScanPackagesVMImage scans a VM image filesystem using OSV-Scalibr.
// The provided fs.FS must implement fs.ReadDirFS and fs.StatFS (which scalibrfs.FS requires).
//
// Performance Note: VM image scanning uses pure Go filesystem parsing for portability
// (no root required, no kernel mounts). This is slower than kernel-mounted filesystems.
// Large images (>5GB virtual size) may take 2-5 minutes to scan.
//
// TODO(performance): Consider these optimizations to improve VM image scan performance:
//   - Path filtering: Skip known-uninteresting directories (/usr/share/doc, /var/cache, etc.)
//   - Parallel extraction: Run multiple extractors concurrently on different paths
//   - Metadata caching: Cache ext4 inode/block lookups for repeated access patterns
//   - Early termination: Stop filesystem traversal once all package databases are found
//   - Progress reporting: Add scan progress callbacks for better UX on large images
//
// See also: docs/guides/vm-images.md for user-facing performance guidance.
func ScanPackagesVMImage(ctx context.Context, fsys scalibrfs.FS, opts ScanOptions) ([]*extractor.Package, error) {
	if fsys == nil {
		return nil, fmt.Errorf("filesystem is required")
	}

	cap := vmImageCapabilities()
	plugins, err := resolvePlugins(opts, cap)
	if err != nil {
		return nil, err
	}
	plugins = filterInventoryPlugins(plugins)

	cfg := &scalibr.ScanConfig{
		ScanRoots: []*scalibrfs.ScanRoot{
			{FS: fsys, Path: ""},
		},
		Plugins:      plugins,
		Capabilities: cap,
	}

	result := scalibr.New().Scan(ctx, cfg)
	pkgs := result.Inventory.Packages
	if scanErr := summarizeScanFailures(result); scanErr != nil {
		if len(pkgs) > 0 {
			return pkgs, scanErr
		}
		return nil, scanErr
	}
	return pkgs, nil
}

// vmImageCapabilities returns capabilities for VM image scanning.
// VM images are treated similarly to container images: Linux filesystem, no network, no direct FS.
func vmImageCapabilities() *plugin.Capabilities {
	return &plugin.Capabilities{
		OS:            plugin.OSLinux,
		Network:       plugin.NetworkOffline,
		DirectFS:      false,
		RunningSystem: false,
	}
}
