// Package workspace provides Docker-specific workspace isolation.
package workspace

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
)

// DockerIsolator provides workspace isolation using Docker-native mechanisms.
// Unlike the host-based isolators, this works without root privileges and
// leverages Docker's overlay storage driver.
type DockerIsolator struct {
	cfg           Config
	masker        *FileMasker
	isolatedPath  string
	upperDir      string
	setupDone     bool
}

// NewDockerIsolator creates a Docker-aware workspace isolator.
func NewDockerIsolator(cfg Config, masker *FileMasker) (*DockerIsolator, error) {
	if cfg.OriginalPath == "" {
		return nil, fmt.Errorf("original path is required")
	}

	absPath, err := filepath.Abs(cfg.OriginalPath)
	if err != nil {
		return nil, fmt.Errorf("resolve original path: %w", err)
	}
	cfg.OriginalPath = absPath

	if cfg.SetupTimeout == 0 {
		cfg.SetupTimeout = 60 * time.Second
	}
	if cfg.OverlaySizeLimit == "" {
		cfg.OverlaySizeLimit = "1g"
	}

	return &DockerIsolator{
		cfg:    cfg,
		masker: masker,
	}, nil
}

// Setup prepares the isolated workspace for Docker.
// For Docker, we create a local copy with masking applied, then mount it.
func (d *DockerIsolator) Setup(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, d.cfg.SetupTimeout)
	defer cancel()

	// Create temporary directory for isolated workspace
	var err error
	d.isolatedPath, err = os.MkdirTemp("", "deputy-docker-workspace-*")
	if err != nil {
		return "", fmt.Errorf("create temp directory: %w", err)
	}

	// Create upper directory for tracking changes (if using overlay mode)
	if d.cfg.Mode == sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_OVERLAY ||
		d.cfg.Mode == sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_TMPFS {
		d.upperDir, err = os.MkdirTemp("", "deputy-docker-upper-*")
		if err != nil {
			os.RemoveAll(d.isolatedPath)
			return "", fmt.Errorf("create upper directory: %w", err)
		}
	}

	// Copy workspace with masking applied
	if d.masker != nil {
		if err := d.masker.CreateMaskedWorkspace(d.cfg.OriginalPath, d.isolatedPath); err != nil {
			d.cleanup()
			return "", fmt.Errorf("create masked workspace: %w", err)
		}
	} else {
		// No masking, just copy
		if err := copyDir(ctx, d.cfg.OriginalPath, d.isolatedPath); err != nil {
			d.cleanup()
			return "", fmt.Errorf("copy workspace: %w", err)
		}
	}

	d.setupDone = true
	return d.isolatedPath, nil
}

// Teardown cleans up the isolated workspace.
func (d *DockerIsolator) Teardown(ctx context.Context, preserveChanges bool) error {
	if !d.setupDone {
		return nil
	}

	if preserveChanges || d.cfg.PreserveAfterExecution {
		return nil
	}

	return d.cleanup()
}

func (d *DockerIsolator) cleanup() error {
	var errs []error
	if d.isolatedPath != "" {
		if err := os.RemoveAll(d.isolatedPath); err != nil {
			errs = append(errs, err)
		}
	}
	if d.upperDir != "" {
		if err := os.RemoveAll(d.upperDir); err != nil {
			errs = append(errs, err)
		}
	}
	// Use errors.Join (Go 1.20+) for cleaner multi-error handling
	return errors.Join(errs...)
}

// Changes returns files modified in the isolated workspace.
func (d *DockerIsolator) Changes(ctx context.Context) ([]FileChange, error) {
	if !d.setupDone {
		return nil, fmt.Errorf("workspace not set up")
	}

	return diffDirectories(d.cfg.OriginalPath, d.isolatedPath)
}

// Sync copies changes from isolated workspace back to original.
func (d *DockerIsolator) Sync(ctx context.Context, patterns, excludePatterns []string) error {
	if !d.setupDone {
		return fmt.Errorf("workspace not set up")
	}

	changes, err := d.Changes(ctx)
	if err != nil {
		return err
	}

	return syncChanges(d.isolatedPath, d.cfg.OriginalPath, changes, patterns, excludePatterns)
}

// IsolatedPath returns the path to the isolated workspace.
func (d *DockerIsolator) IsolatedPath() string {
	return d.isolatedPath
}

// OriginalPath returns the original workspace path.
func (d *DockerIsolator) OriginalPath() string {
	return d.cfg.OriginalPath
}

// BuildMounts returns Docker mount configurations for the isolated workspace.
// This configures how the workspace should be mounted into the container.
func (d *DockerIsolator) BuildMounts(containerWorkspace string, readOnly bool) []mount.Mount {
	mounts := []mount.Mount{
		{
			Type:     mount.TypeBind,
			Source:   d.isolatedPath,
			Target:   containerWorkspace,
			ReadOnly: readOnly,
		},
	}

	return mounts
}

// BuildHiddenPathMounts returns tmpfs mounts for hiding files inside the container.
// This is used when file masking is done at container runtime rather than by copying.
func (d *DockerIsolator) BuildHiddenPathMounts(containerWorkspace string) []mount.Mount {
	if d.masker == nil {
		return nil
	}

	var mounts []mount.Mount
	hiddenPaths := d.masker.GenerateHiddenPaths(d.cfg.OriginalPath)

	for _, path := range hiddenPaths {
		// Convert workspace path to container path
		containerPath := strings.Replace(path, "/workspace", containerWorkspace, 1)
		mounts = append(mounts, mount.Mount{
			Type:   mount.TypeTmpfs,
			Target: containerPath,
			TmpfsOptions: &mount.TmpfsOptions{
				SizeBytes: 0, // Empty tmpfs to hide the path
				Mode:      0,
			},
		})
	}

	return mounts
}

// ApplyToHostConfig applies isolation settings to Docker HostConfig.
// This sets up tmpfs, mounts, and other container configuration.
func (d *DockerIsolator) ApplyToHostConfig(hostConfig *container.HostConfig, containerWorkspace string, mode sandboxv1.Mode) {
	// Main workspace mount
	readOnly := mode == sandboxv1.Mode_MODE_READ_ONLY
	hostConfig.Mounts = append(hostConfig.Mounts, d.BuildMounts(containerWorkspace, readOnly)...)

	// Hidden path mounts (tmpfs overlay)
	hostConfig.Mounts = append(hostConfig.Mounts, d.BuildHiddenPathMounts(containerWorkspace)...)

	// For overlay/tmpfs modes, add tmpfs for ephemeral data
	if d.cfg.Mode == sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_TMPFS {
		if hostConfig.Tmpfs == nil {
			hostConfig.Tmpfs = make(map[string]string)
		}
		// Add tmpfs for /tmp with size limit
		hostConfig.Tmpfs["/tmp"] = fmt.Sprintf("size=%s,mode=1777", d.cfg.OverlaySizeLimit)
	}
}

// DockerIsolationOptions holds options for Docker-specific workspace isolation.
type DockerIsolationOptions struct {
	// Mode is the workspace isolation mode.
	Mode sandboxv1.WorkspaceIsolationMode

	// FileMask configuration for hiding sensitive files.
	FileMask *sandboxv1.FileMaskConfig

	// OriginalPath is the host workspace path.
	OriginalPath string

	// ContainerPath is where the workspace is mounted in the container.
	ContainerPath string

	// SizeLimit for overlay/tmpfs upper layer.
	SizeLimit string

	// SyncPatterns for selective file sync after execution.
	SyncPatterns []string

	// ExcludeSyncPatterns for files to never sync.
	ExcludeSyncPatterns []string

	// PreserveAfterExecution keeps workspace for review.
	PreserveAfterExecution bool
}

// NewDockerIsolationFromOptions creates a DockerIsolator from options.
func NewDockerIsolationFromOptions(opts DockerIsolationOptions) (*DockerIsolator, error) {
	var masker *FileMasker
	if opts.FileMask != nil {
		masker = NewFileMasker(opts.FileMask)
	}

	cfg := Config{
		Mode:                   opts.Mode,
		OriginalPath:           opts.OriginalPath,
		OverlaySizeLimit:       opts.SizeLimit,
		SyncPatterns:           opts.SyncPatterns,
		ExcludeSyncPatterns:    opts.ExcludeSyncPatterns,
		PreserveAfterExecution: opts.PreserveAfterExecution,
	}

	return NewDockerIsolator(cfg, masker)
}

// DefaultDockerIsolation returns recommended defaults for Docker isolation.
func DefaultDockerIsolation(workspacePath string) DockerIsolationOptions {
	return DockerIsolationOptions{
		Mode:          sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		FileMask:      DefaultSupplyChainMask(),
		OriginalPath:  workspacePath,
		ContainerPath: "/workspace",
		SizeLimit:     "1g",
	}
}

// AgentDockerIsolation returns isolation settings optimized for AI agents.
func AgentDockerIsolation(workspacePath string) DockerIsolationOptions {
	return DockerIsolationOptions{
		Mode:          sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		FileMask:      DefaultAgentMask(),
		OriginalPath:  workspacePath,
		ContainerPath: "/workspace",
		SizeLimit:     "2g", // Larger for AI operations
		SyncPatterns: []string{
			// Only sync dependency files by default
			"package.json",
			"package-lock.json",
			"go.mod",
			"go.sum",
			"Cargo.toml",
			"Cargo.lock",
			"requirements.txt",
			"pyproject.toml",
		},
		PreserveAfterExecution: true, // Review changes before applying
	}
}
