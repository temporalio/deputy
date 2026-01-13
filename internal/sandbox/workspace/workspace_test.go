package workspace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
)

func TestNewIsolator(t *testing.T) {
	tests := []struct {
		name    string
		mode    sandboxv1.WorkspaceIsolationMode
		wantErr bool
	}{
		{
			name:    "unspecified mode returns direct",
			mode:    sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_UNSPECIFIED,
			wantErr: false,
		},
		{
			name:    "direct mode",
			mode:    sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_DIRECT,
			wantErr: false,
		},
		{
			name:    "snapshot mode",
			mode:    sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			cfg := Config{
				Mode:         tc.mode,
				OriginalPath: tmpDir,
			}

			isolator, err := New(cfg)
			if (err != nil) != tc.wantErr {
				t.Fatalf("New() error = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && isolator == nil {
				t.Fatal("New() returned nil isolator")
			}
		})
	}
}

func TestDirectIsolator(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_DIRECT,
		OriginalPath: tmpDir,
	}

	isolator, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Setup should return original path
	path, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	if path != tmpDir {
		t.Errorf("Setup() = %q, want %q", path, tmpDir)
	}

	// IsolatedPath should equal OriginalPath
	if isolator.IsolatedPath() != isolator.OriginalPath() {
		t.Errorf("IsolatedPath() = %q, OriginalPath() = %q, should be equal",
			isolator.IsolatedPath(), isolator.OriginalPath())
	}

	// Teardown should be a no-op
	if err := isolator.Teardown(ctx, false); err != nil {
		t.Errorf("Teardown() error = %v", err)
	}

	// File should still exist
	if _, err := os.Stat(testFile); err != nil {
		t.Errorf("File disappeared after teardown: %v", err)
	}
}

func TestSnapshotIsolator(t *testing.T) {
	// Create source directory with test files
	srcDir := t.TempDir()
	testFile := filepath.Join(srcDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}

	subDir := filepath.Join(srcDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	subFile := filepath.Join(subDir, "sub.txt")
	if err := os.WriteFile(subFile, []byte("subfile"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
		SetupTimeout: 30 * time.Second,
	}

	isolator, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Setup should create snapshot
	snapshotPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	// Snapshot should be different from original
	if snapshotPath == srcDir {
		t.Error("Snapshot path should be different from original")
	}

	// Files should exist in snapshot
	snapshotFile := filepath.Join(snapshotPath, "test.txt")
	if _, err := os.Stat(snapshotFile); err != nil {
		t.Errorf("File missing from snapshot: %v", err)
	}

	// Modify snapshot file
	if err := os.WriteFile(snapshotFile, []byte("modified"), 0644); err != nil {
		t.Fatal(err)
	}

	// Original should be unchanged
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "original" {
		t.Errorf("Original file was modified: %q", content)
	}

	// Get changes
	changes, err := isolator.Changes(ctx)
	if err != nil {
		t.Fatalf("Changes() error = %v", err)
	}

	foundModified := false
	for _, change := range changes {
		if change.Path == "test.txt" && change.Type == "modified" {
			foundModified = true
			break
		}
	}
	if !foundModified {
		t.Error("Changes() should report test.txt as modified")
	}

	// Cleanup
	if err := isolator.Teardown(ctx, false); err != nil {
		t.Errorf("Teardown() error = %v", err)
	}

	// Snapshot directory should be removed
	if _, err := os.Stat(snapshotPath); !os.IsNotExist(err) {
		t.Error("Snapshot directory should be removed after teardown")
	}
}

func TestSnapshotIsolatorSync(t *testing.T) {
	// Create source directory
	srcDir := t.TempDir()
	testFile := filepath.Join(srcDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
		SetupTimeout: 30 * time.Second,
	}

	isolator, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	snapshotPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer isolator.Teardown(ctx, false)

	// Modify file in snapshot
	snapshotFile := filepath.Join(snapshotPath, "test.txt")
	if err := os.WriteFile(snapshotFile, []byte("modified"), 0644); err != nil {
		t.Fatal(err)
	}

	// Add new file
	newFile := filepath.Join(snapshotPath, "new.txt")
	if err := os.WriteFile(newFile, []byte("new content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Sync changes back
	if err := isolator.Sync(ctx, nil, nil); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	// Verify original file is now modified
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "modified" {
		t.Errorf("Original file not synced: %q", content)
	}

	// Verify new file exists
	newOrigFile := filepath.Join(srcDir, "new.txt")
	content, err = os.ReadFile(newOrigFile)
	if err != nil {
		t.Fatalf("New file not synced: %v", err)
	}
	if string(content) != "new content" {
		t.Errorf("New file content incorrect: %q", content)
	}
}

func TestSnapshotIsolatorSyncPatterns(t *testing.T) {
	// Create source directory
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "include.txt"), []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "exclude.txt"), []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
		SetupTimeout: 30 * time.Second,
	}

	isolator, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	snapshotPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer isolator.Teardown(ctx, false)

	// Modify both files
	if err := os.WriteFile(filepath.Join(snapshotPath, "include.txt"), []byte("modified"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(snapshotPath, "exclude.txt"), []byte("modified"), 0644); err != nil {
		t.Fatal(err)
	}

	// Sync only include.txt
	if err := isolator.Sync(ctx, []string{"*.txt"}, []string{"exclude.txt"}); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	// include.txt should be synced
	content, err := os.ReadFile(filepath.Join(srcDir, "include.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "modified" {
		t.Errorf("include.txt should be synced: %q", content)
	}

	// exclude.txt should NOT be synced
	content, err = os.ReadFile(filepath.Join(srcDir, "exclude.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "original" {
		t.Errorf("exclude.txt should not be synced: %q", content)
	}
}

func TestGitWorktreeIsolator(t *testing.T) {
	// Skip if git is not available
	if _, err := os.Stat("/usr/bin/git"); os.IsNotExist(err) {
		t.Skip("git not available")
	}

	// Create a git repository
	repoDir := t.TempDir()

	// Initialize git repo
	ctx := context.Background()
	runGit := func(args ...string) error {
		cmd := newExecCommand(ctx, "git", args...)
		cmd.Dir = repoDir
		return cmd.Run()
	}

	if err := runGit("init"); err != nil {
		t.Fatalf("git init failed: %v", err)
	}
	if err := runGit("config", "user.email", "test@test.com"); err != nil {
		t.Fatalf("git config failed: %v", err)
	}
	if err := runGit("config", "user.name", "Test"); err != nil {
		t.Fatalf("git config failed: %v", err)
	}

	// Create initial commit
	testFile := filepath.Join(repoDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("original"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := runGit("add", "."); err != nil {
		t.Fatalf("git add failed: %v", err)
	}
	if err := runGit("commit", "-m", "initial"); err != nil {
		t.Fatalf("git commit failed: %v", err)
	}

	cfg := Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_GIT_WORKTREE,
		OriginalPath: repoDir,
		SetupTimeout: 30 * time.Second,
	}

	isolator, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	worktreePath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	// Worktree should be different from original
	if worktreePath == repoDir {
		t.Error("Worktree path should be different from original")
	}

	// File should exist in worktree
	wtFile := filepath.Join(worktreePath, "test.txt")
	if _, err := os.Stat(wtFile); err != nil {
		t.Errorf("File missing from worktree: %v", err)
	}

	// Cleanup
	if err := isolator.Teardown(ctx, false); err != nil {
		t.Errorf("Teardown() error = %v", err)
	}
}

func TestConfigDefaults(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: tmpDir,
	}

	isolator, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Check that defaults are applied
	snapshotIsolator, ok := isolator.(*snapshotIsolator)
	if !ok {
		t.Fatal("Expected snapshotIsolator")
	}

	if snapshotIsolator.cfg.SetupTimeout != 60*time.Second {
		t.Errorf("SetupTimeout = %v, want 60s", snapshotIsolator.cfg.SetupTimeout)
	}
}

func TestDiffDirectories(t *testing.T) {
	// Create original directory
	origDir := t.TempDir()
	os.WriteFile(filepath.Join(origDir, "unchanged.txt"), []byte("same"), 0644)
	os.WriteFile(filepath.Join(origDir, "modified.txt"), []byte("original"), 0644)
	os.WriteFile(filepath.Join(origDir, "deleted.txt"), []byte("will delete"), 0644)

	// Create modified directory
	modDir := t.TempDir()
	os.WriteFile(filepath.Join(modDir, "unchanged.txt"), []byte("same"), 0644)
	os.WriteFile(filepath.Join(modDir, "modified.txt"), []byte("changed"), 0644)
	os.WriteFile(filepath.Join(modDir, "added.txt"), []byte("new"), 0644)
	// deleted.txt is not copied

	changes, err := diffDirectories(origDir, modDir)
	if err != nil {
		t.Fatal(err)
	}

	changeMap := make(map[string]string)
	for _, c := range changes {
		changeMap[c.Path] = c.Type
	}

	if changeMap["added.txt"] != "added" {
		t.Errorf("added.txt should be 'added', got %q", changeMap["added.txt"])
	}
	if changeMap["deleted.txt"] != "deleted" {
		t.Errorf("deleted.txt should be 'deleted', got %q", changeMap["deleted.txt"])
	}
	// modified.txt might or might not show up depending on mod time
}

func TestMatchesAnyPattern(t *testing.T) {
	tests := []struct {
		path     string
		patterns []string
		want     bool
	}{
		{"test.txt", []string{"*.txt"}, true},
		{"test.go", []string{"*.txt"}, false},
		{"dir/test.txt", []string{"*.txt"}, true},
		{"package-lock.json", []string{"package-lock.json"}, true},
		{"node_modules/pkg/package.json", []string{"package.json"}, true},
		{"test.txt", []string{}, false},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			got := matchesAnyPattern(tc.path, tc.patterns)
			if got != tc.want {
				t.Errorf("matchesAnyPattern(%q, %v) = %v, want %v",
					tc.path, tc.patterns, got, tc.want)
			}
		})
	}
}

// newExecCommand is a test helper to create exec.Command with context.
func newExecCommand(ctx context.Context, name string, args ...string) *execCmd {
	return &execCmd{ctx: ctx, name: name, args: args}
}

type execCmd struct {
	ctx  context.Context
	name string
	args []string
	Dir  string
}

func (c *execCmd) Run() error {
	cmd := exec.CommandContext(c.ctx, c.name, c.args...)
	cmd.Dir = c.Dir
	return cmd.Run()
}
