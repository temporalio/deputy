package workspace

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/moby/api/types/container"
	sandboxv1 "github.com/temporalio/deputy/gen/deputy/sandbox/v1"
)

func TestNewDockerIsolator(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
				OriginalPath: tmpDir,
			},
			wantErr: false,
		},
		{
			name: "empty original path",
			cfg: Config{
				Mode: sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDockerIsolator(tc.cfg, nil)
			if (err != nil) != tc.wantErr {
				t.Errorf("NewDockerIsolator() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestDockerIsolatorSetupAndTeardown(t *testing.T) {
	// Create source directory with test files
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "test.txt"), []byte("hello"), 0644)
	os.WriteFile(filepath.Join(srcDir, ".env"), []byte("SECRET=value"), 0644)

	// Create isolator with secrets masking
	masker := NewFileMasker(&sandboxv1.FileMaskConfig{
		Presets: []sandboxv1.FileMaskPreset{
			sandboxv1.FileMaskPreset_FILE_MASK_PRESET_SECRETS,
		},
	})

	isolator, err := NewDockerIsolator(Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
	}, masker)
	if err != nil {
		t.Fatalf("NewDockerIsolator() error = %v", err)
	}

	ctx := context.Background()

	// Setup
	isolatedPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	// Verify isolated path exists
	if _, err := os.Stat(isolatedPath); os.IsNotExist(err) {
		t.Error("isolated path should exist")
	}

	// Verify test.txt was copied
	if _, err := os.Stat(filepath.Join(isolatedPath, "test.txt")); os.IsNotExist(err) {
		t.Error("test.txt should exist in isolated workspace")
	}

	// Verify .env was masked (hidden)
	if _, err := os.Stat(filepath.Join(isolatedPath, ".env")); !os.IsNotExist(err) {
		t.Error(".env should be hidden in isolated workspace")
	}

	// Teardown
	if err := isolator.Teardown(ctx, false); err != nil {
		t.Errorf("Teardown() error = %v", err)
	}

	// Verify cleanup
	if _, err := os.Stat(isolatedPath); !os.IsNotExist(err) {
		t.Error("isolated path should be cleaned up")
	}
}

func TestDockerIsolatorPreserveChanges(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "test.txt"), []byte("hello"), 0644)

	isolator, err := NewDockerIsolator(Config{
		Mode:                   sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath:           srcDir,
		PreserveAfterExecution: true,
	}, nil)
	if err != nil {
		t.Fatalf("NewDockerIsolator() error = %v", err)
	}

	ctx := context.Background()
	isolatedPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	// Teardown with preserve=false but config has PreserveAfterExecution=true
	if err := isolator.Teardown(ctx, false); err != nil {
		t.Errorf("Teardown() error = %v", err)
	}

	// Isolated path should still exist
	if _, err := os.Stat(isolatedPath); os.IsNotExist(err) {
		t.Error("isolated path should be preserved")
	}

	// Clean up manually for test
	os.RemoveAll(isolatedPath)
}

func TestDockerIsolatorChanges(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "original.txt"), []byte("original"), 0644)

	isolator, err := NewDockerIsolator(Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
	}, nil)
	if err != nil {
		t.Fatalf("NewDockerIsolator() error = %v", err)
	}

	ctx := context.Background()
	isolatedPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer isolator.Teardown(ctx, false)

	// Make changes in isolated workspace
	os.WriteFile(filepath.Join(isolatedPath, "new.txt"), []byte("new file"), 0644)
	os.WriteFile(filepath.Join(isolatedPath, "original.txt"), []byte("modified"), 0644)

	// Get changes
	changes, err := isolator.Changes(ctx)
	if err != nil {
		t.Fatalf("Changes() error = %v", err)
	}

	// Should have at least the new file and modified file
	if len(changes) < 2 {
		t.Errorf("expected at least 2 changes, got %d", len(changes))
	}

	foundNew := false
	foundModified := false
	for _, c := range changes {
		if c.Path == "new.txt" && c.Type == "added" {
			foundNew = true
		}
		if c.Path == "original.txt" && c.Type == "modified" {
			foundModified = true
		}
	}

	if !foundNew {
		t.Error("expected to find new.txt as added")
	}
	if !foundModified {
		t.Error("expected to find original.txt as modified")
	}
}

func TestDockerIsolatorBuildMounts(t *testing.T) {
	srcDir := t.TempDir()

	isolator, err := NewDockerIsolator(Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
	}, nil)
	if err != nil {
		t.Fatalf("NewDockerIsolator() error = %v", err)
	}

	ctx := context.Background()
	isolatedPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer isolator.Teardown(ctx, false)

	// Build mounts
	mounts := isolator.BuildMounts("/workspace", false)
	if len(mounts) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(mounts))
	}

	mount := mounts[0]
	if mount.Source != isolatedPath {
		t.Errorf("mount source = %q, want %q", mount.Source, isolatedPath)
	}
	if mount.Target != "/workspace" {
		t.Errorf("mount target = %q, want %q", mount.Target, "/workspace")
	}
	if mount.ReadOnly != false {
		t.Error("mount should not be read-only")
	}

	// Test read-only mount
	roMounts := isolator.BuildMounts("/workspace", true)
	if !roMounts[0].ReadOnly {
		t.Error("mount should be read-only")
	}
}

func TestDockerIsolatorApplyToHostConfig(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "test.txt"), []byte("test"), 0644)

	isolator, err := NewDockerIsolator(Config{
		Mode:             sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_TMPFS,
		OriginalPath:     srcDir,
		OverlaySizeLimit: "512m",
	}, nil)
	if err != nil {
		t.Fatalf("NewDockerIsolator() error = %v", err)
	}

	ctx := context.Background()
	if _, err := isolator.Setup(ctx); err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer isolator.Teardown(ctx, false)

	hostConfig := &container.HostConfig{}
	isolator.ApplyToHostConfig(hostConfig, "/workspace", sandboxv1.Mode_MODE_WORKSPACE_WRITE)

	// Should have workspace mount
	if len(hostConfig.Mounts) < 1 {
		t.Error("expected at least 1 mount")
	}

	// Should have tmpfs for /tmp in TMPFS mode
	if hostConfig.Tmpfs == nil {
		t.Error("expected tmpfs configuration")
	}
	if _, ok := hostConfig.Tmpfs["/tmp"]; !ok {
		t.Error("expected /tmp tmpfs")
	}
}

func TestDefaultDockerIsolation(t *testing.T) {
	opts := DefaultDockerIsolation("/test/workspace")

	if opts.Mode != sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT {
		t.Errorf("expected SNAPSHOT mode, got %v", opts.Mode)
	}
	if opts.OriginalPath != "/test/workspace" {
		t.Errorf("expected /test/workspace, got %s", opts.OriginalPath)
	}
	if opts.FileMask == nil {
		t.Error("expected file mask to be set")
	}
	if opts.SizeLimit != "1g" {
		t.Errorf("expected 1g size limit, got %s", opts.SizeLimit)
	}
}

func TestAgentDockerIsolation(t *testing.T) {
	opts := AgentDockerIsolation("/test/workspace")

	if opts.Mode != sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT {
		t.Errorf("expected SNAPSHOT mode, got %v", opts.Mode)
	}
	if opts.SizeLimit != "2g" {
		t.Errorf("expected 2g size limit, got %s", opts.SizeLimit)
	}
	if !opts.PreserveAfterExecution {
		t.Error("expected PreserveAfterExecution to be true")
	}
	if len(opts.SyncPatterns) == 0 {
		t.Error("expected sync patterns to be set")
	}

	// Check that common dependency files are in sync patterns
	expectedPatterns := []string{"package.json", "go.mod", "Cargo.toml"}
	for _, expected := range expectedPatterns {
		found := false
		for _, pattern := range opts.SyncPatterns {
			if pattern == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q in sync patterns", expected)
		}
	}
}

func TestNewDockerIsolationFromOptions(t *testing.T) {
	tmpDir := t.TempDir()

	opts := DockerIsolationOptions{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: tmpDir,
		FileMask:     DefaultSupplyChainMask(),
		SizeLimit:    "2g",
		SyncPatterns: []string{"*.json"},
	}

	isolator, err := NewDockerIsolationFromOptions(opts)
	if err != nil {
		t.Fatalf("NewDockerIsolationFromOptions() error = %v", err)
	}

	if isolator.cfg.OverlaySizeLimit != "2g" {
		t.Errorf("expected size limit 2g, got %s", isolator.cfg.OverlaySizeLimit)
	}
	if isolator.masker == nil {
		t.Error("expected masker to be set")
	}
}
