// Package workspace provides workspace isolation modes for sandbox execution.
//
// Workspace isolation controls how the sandbox interacts with the host filesystem,
// providing defense-in-depth for supply chain security. Available modes:
//
//   - Direct: Simple bind mount (default, backward compatible)
//   - Overlay: Copy-on-write using overlayfs
//   - Snapshot: Full copy to temporary directory
//   - GitWorktree: Git worktree for repository isolation
//   - Tmpfs: In-memory overlay for ephemeral operations
//
// Each mode offers different tradeoffs between performance, isolation, and
// the ability to review/rollback changes.
package workspace

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
)

// Isolator manages workspace isolation for sandbox execution.
// It handles setup, teardown, and change synchronization.
type Isolator interface {
	// Setup prepares the isolated workspace and returns the path to use.
	// The returned path should be mounted into the sandbox.
	Setup(ctx context.Context) (isolatedPath string, err error)

	// Teardown cleans up the isolated workspace.
	// If preserveChanges is true, modified files are kept for review.
	Teardown(ctx context.Context, preserveChanges bool) error

	// Changes returns the list of files modified during execution.
	// Only available after sandbox execution completes.
	Changes(ctx context.Context) ([]FileChange, error)

	// Sync copies changes from isolated workspace back to original.
	// Respects sync_patterns and exclude_sync_patterns from config.
	Sync(ctx context.Context, patterns, excludePatterns []string) error

	// IsolatedPath returns the path to the isolated workspace.
	IsolatedPath() string

	// OriginalPath returns the original workspace path.
	OriginalPath() string
}

// FileChange represents a file that was modified in the isolated workspace.
type FileChange struct {
	// Path relative to workspace root.
	Path string

	// Type of change: "added", "modified", "deleted", "renamed".
	Type string

	// OldPath for renamed files.
	OldPath string

	// Size in bytes (0 for deleted files).
	Size int64

	// ModTime of the file.
	ModTime time.Time
}

// Config configures workspace isolation behavior.
type Config struct {
	// Mode determines the isolation strategy.
	Mode sandboxv1.WorkspaceIsolationMode

	// OriginalPath is the original workspace directory.
	OriginalPath string

	// OverlaySizeLimit for overlay modes (e.g., "1g").
	OverlaySizeLimit string

	// SnapshotDir for snapshot mode.
	SnapshotDir string

	// WorktreeBranch for git worktree mode.
	WorktreeBranch string

	// PreserveAfterExecution keeps the isolated workspace for review.
	PreserveAfterExecution bool

	// SetupTimeout limits time spent setting up isolation.
	SetupTimeout time.Duration

	// SyncPatterns are glob patterns for files to sync back.
	SyncPatterns []string

	// ExcludeSyncPatterns are glob patterns for files to never sync.
	ExcludeSyncPatterns []string
}

// New creates a new workspace isolator based on the configuration.
func New(cfg Config) (Isolator, error) {
	if cfg.OriginalPath == "" {
		return nil, fmt.Errorf("original path is required")
	}

	// Validate and clean the path
	absPath, err := filepath.Abs(cfg.OriginalPath)
	if err != nil {
		return nil, fmt.Errorf("resolve original path: %w", err)
	}
	cfg.OriginalPath = absPath

	// Set defaults
	if cfg.SetupTimeout == 0 {
		cfg.SetupTimeout = 60 * time.Second
	}
	if cfg.OverlaySizeLimit == "" {
		cfg.OverlaySizeLimit = "1g"
	}

	switch cfg.Mode {
	case sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_UNSPECIFIED,
		sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_DIRECT:
		return &directIsolator{cfg: cfg}, nil

	case sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_OVERLAY:
		return newOverlayIsolator(cfg)

	case sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT:
		return newSnapshotIsolator(cfg)

	case sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_GIT_WORKTREE:
		return newGitWorktreeIsolator(cfg)

	case sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_TMPFS:
		return newTmpfsIsolator(cfg)

	default:
		return nil, fmt.Errorf("unsupported isolation mode: %v", cfg.Mode)
	}
}

// directIsolator provides no isolation - direct bind mount (default).
type directIsolator struct {
	cfg Config
}

func (d *directIsolator) Setup(ctx context.Context) (string, error) {
	return d.cfg.OriginalPath, nil
}

func (d *directIsolator) Teardown(ctx context.Context, preserveChanges bool) error {
	return nil
}

func (d *directIsolator) Changes(ctx context.Context) ([]FileChange, error) {
	return nil, fmt.Errorf("change tracking not available in direct mode")
}

func (d *directIsolator) Sync(ctx context.Context, patterns, excludePatterns []string) error {
	return nil // No-op in direct mode
}

func (d *directIsolator) IsolatedPath() string {
	return d.cfg.OriginalPath
}

func (d *directIsolator) OriginalPath() string {
	return d.cfg.OriginalPath
}

// snapshotIsolator copies workspace to a temporary directory.
type snapshotIsolator struct {
	cfg          Config
	snapshotPath string
	setupDone    bool
}

func newSnapshotIsolator(cfg Config) (*snapshotIsolator, error) {
	return &snapshotIsolator{cfg: cfg}, nil
}

func (s *snapshotIsolator) Setup(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.SetupTimeout)
	defer cancel()

	// Create snapshot directory
	var err error
	if s.cfg.SnapshotDir != "" {
		s.snapshotPath = filepath.Join(s.cfg.SnapshotDir, fmt.Sprintf("snapshot-%d", time.Now().UnixNano()))
		if err := os.MkdirAll(s.snapshotPath, 0755); err != nil {
			return "", fmt.Errorf("create snapshot directory: %w", err)
		}
	} else {
		s.snapshotPath, err = os.MkdirTemp("", "deputy-snapshot-*")
		if err != nil {
			return "", fmt.Errorf("create temp directory: %w", err)
		}
	}

	// Copy workspace to snapshot
	if err := copyDir(ctx, s.cfg.OriginalPath, s.snapshotPath); err != nil {
		_ = os.RemoveAll(s.snapshotPath)
		return "", fmt.Errorf("copy workspace: %w", err)
	}

	s.setupDone = true
	return s.snapshotPath, nil
}

func (s *snapshotIsolator) Teardown(ctx context.Context, preserveChanges bool) error {
	if !s.setupDone {
		return nil
	}

	if preserveChanges || s.cfg.PreserveAfterExecution {
		return nil
	}

	return os.RemoveAll(s.snapshotPath)
}

func (s *snapshotIsolator) Changes(ctx context.Context) ([]FileChange, error) {
	if !s.setupDone {
		return nil, fmt.Errorf("snapshot not set up")
	}

	return diffDirectories(s.cfg.OriginalPath, s.snapshotPath)
}

func (s *snapshotIsolator) Sync(ctx context.Context, patterns, excludePatterns []string) error {
	if !s.setupDone {
		return fmt.Errorf("snapshot not set up")
	}

	changes, err := s.Changes(ctx)
	if err != nil {
		return err
	}

	return syncChanges(s.snapshotPath, s.cfg.OriginalPath, changes, patterns, excludePatterns)
}

func (s *snapshotIsolator) IsolatedPath() string {
	return s.snapshotPath
}

func (s *snapshotIsolator) OriginalPath() string {
	return s.cfg.OriginalPath
}

// gitWorktreeIsolator uses git worktree for repository isolation.
type gitWorktreeIsolator struct {
	cfg          Config
	worktreePath string
	branchName   string
	setupDone    bool
}

func newGitWorktreeIsolator(cfg Config) (*gitWorktreeIsolator, error) {
	// Verify the original path is a git repository
	gitDir := filepath.Join(cfg.OriginalPath, ".git")
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("git worktree mode requires a git repository")
	}
	return &gitWorktreeIsolator{cfg: cfg}, nil
}

func (g *gitWorktreeIsolator) Setup(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, g.cfg.SetupTimeout)
	defer cancel()

	// Generate branch name
	g.branchName = g.cfg.WorktreeBranch
	if g.branchName == "" {
		g.branchName = fmt.Sprintf("deputy-sandbox-%d", time.Now().UnixNano())
	}

	// Create worktree directory
	var err error
	g.worktreePath, err = os.MkdirTemp("", "deputy-worktree-*")
	if err != nil {
		return "", fmt.Errorf("create worktree directory: %w", err)
	}

	// Create the worktree
	cmd := exec.CommandContext(ctx, "git", "worktree", "add", "-b", g.branchName, g.worktreePath)
	cmd.Dir = g.cfg.OriginalPath
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(g.worktreePath)
		return "", fmt.Errorf("create git worktree: %s: %w", output, err)
	}

	g.setupDone = true
	return g.worktreePath, nil
}

func (g *gitWorktreeIsolator) Teardown(ctx context.Context, preserveChanges bool) error {
	if !g.setupDone {
		return nil
	}

	if preserveChanges || g.cfg.PreserveAfterExecution {
		return nil
	}

	// Remove the worktree
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "worktree", "remove", "--force", g.worktreePath)
	cmd.Dir = g.cfg.OriginalPath
	_ = cmd.Run()

	// Delete the branch
	cmd = exec.CommandContext(ctx, "git", "branch", "-D", g.branchName)
	cmd.Dir = g.cfg.OriginalPath
	_ = cmd.Run()

	return nil
}

func (g *gitWorktreeIsolator) Changes(ctx context.Context) ([]FileChange, error) {
	if !g.setupDone {
		return nil, fmt.Errorf("worktree not set up")
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Get changes using git diff
	cmd := exec.CommandContext(ctx, "git", "diff", "--name-status", "HEAD")
	cmd.Dir = g.worktreePath
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}

	return parseGitDiff(string(output))
}

func (g *gitWorktreeIsolator) Sync(ctx context.Context, patterns, excludePatterns []string) error {
	if !g.setupDone {
		return fmt.Errorf("worktree not set up")
	}

	changes, err := g.Changes(ctx)
	if err != nil {
		return err
	}

	return syncChanges(g.worktreePath, g.cfg.OriginalPath, changes, patterns, excludePatterns)
}

func (g *gitWorktreeIsolator) IsolatedPath() string {
	return g.worktreePath
}

func (g *gitWorktreeIsolator) OriginalPath() string {
	return g.cfg.OriginalPath
}

// overlayIsolator uses overlayfs for copy-on-write isolation.
type overlayIsolator struct {
	cfg          Config
	upperDir     string
	workDir      string
	mergedDir    string
	setupDone    bool
}

func newOverlayIsolator(cfg Config) (*overlayIsolator, error) {
	return &overlayIsolator{cfg: cfg}, nil
}

func (o *overlayIsolator) Setup(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, o.cfg.SetupTimeout)
	defer cancel()

	// Create temporary directories for overlay
	baseDir, err := os.MkdirTemp("", "deputy-overlay-*")
	if err != nil {
		return "", fmt.Errorf("create base directory: %w", err)
	}

	o.upperDir = filepath.Join(baseDir, "upper")
	o.workDir = filepath.Join(baseDir, "work")
	o.mergedDir = filepath.Join(baseDir, "merged")

	for _, dir := range []string{o.upperDir, o.workDir, o.mergedDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			_ = os.RemoveAll(baseDir)
			return "", fmt.Errorf("create overlay directory %s: %w", dir, err)
		}
	}

	// Mount overlayfs
	// Note: This requires root privileges on Linux
	// For Docker, we use Docker's own overlay mechanism instead
	cmd := exec.CommandContext(ctx, "mount", "-t", "overlay", "overlay",
		"-o", fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", o.cfg.OriginalPath, o.upperDir, o.workDir),
		o.mergedDir)

	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(baseDir)
		return "", fmt.Errorf("mount overlay: %s: %w", output, err)
	}

	o.setupDone = true
	return o.mergedDir, nil
}

func (o *overlayIsolator) Teardown(ctx context.Context, preserveChanges bool) error {
	if !o.setupDone {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Unmount overlay
	cmd := exec.CommandContext(ctx, "umount", o.mergedDir)
	_ = cmd.Run()

	if preserveChanges || o.cfg.PreserveAfterExecution {
		// Keep the upper directory for review
		return nil
	}

	// Clean up all directories
	baseDir := filepath.Dir(o.upperDir)
	return os.RemoveAll(baseDir)
}

func (o *overlayIsolator) Changes(ctx context.Context) ([]FileChange, error) {
	if !o.setupDone {
		return nil, fmt.Errorf("overlay not set up")
	}

	// The upper directory contains all changes
	var changes []FileChange
	err := filepath.Walk(o.upperDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == o.upperDir {
			return nil
		}

		relPath, err := filepath.Rel(o.upperDir, path)
		if err != nil {
			return err
		}

		// Skip .git directory
		if relPath == ".git" || strings.HasPrefix(relPath, ".git"+string(filepath.Separator)) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		changeType := "modified"
		origPath := filepath.Join(o.cfg.OriginalPath, relPath)
		if _, err := os.Stat(origPath); os.IsNotExist(err) {
			changeType = "added"
		}

		changes = append(changes, FileChange{
			Path:    relPath,
			Type:    changeType,
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
		return nil
	})

	return changes, err
}

func (o *overlayIsolator) Sync(ctx context.Context, patterns, excludePatterns []string) error {
	if !o.setupDone {
		return fmt.Errorf("overlay not set up")
	}

	changes, err := o.Changes(ctx)
	if err != nil {
		return err
	}

	return syncChanges(o.upperDir, o.cfg.OriginalPath, changes, patterns, excludePatterns)
}

func (o *overlayIsolator) IsolatedPath() string {
	return o.mergedDir
}

func (o *overlayIsolator) OriginalPath() string {
	return o.cfg.OriginalPath
}

// tmpfsIsolator uses in-memory tmpfs for ephemeral operations.
type tmpfsIsolator struct {
	cfg       Config
	tmpfsPath string
	setupDone bool
}

func newTmpfsIsolator(cfg Config) (*tmpfsIsolator, error) {
	return &tmpfsIsolator{cfg: cfg}, nil
}

func (t *tmpfsIsolator) Setup(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, t.cfg.SetupTimeout)
	defer cancel()

	// Create tmpfs mount point
	var err error
	t.tmpfsPath, err = os.MkdirTemp("", "deputy-tmpfs-*")
	if err != nil {
		return "", fmt.Errorf("create tmpfs mount point: %w", err)
	}

	// Mount tmpfs with size limit
	sizeOpt := fmt.Sprintf("size=%s", t.cfg.OverlaySizeLimit)
	cmd := exec.CommandContext(ctx, "mount", "-t", "tmpfs", "-o", sizeOpt, "tmpfs", t.tmpfsPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(t.tmpfsPath)
		return "", fmt.Errorf("mount tmpfs: %s: %w", output, err)
	}

	// Copy workspace to tmpfs
	if err := copyDir(ctx, t.cfg.OriginalPath, t.tmpfsPath); err != nil {
		_ = exec.CommandContext(ctx, "umount", t.tmpfsPath).Run()
		_ = os.RemoveAll(t.tmpfsPath)
		return "", fmt.Errorf("copy to tmpfs: %w", err)
	}

	t.setupDone = true
	return t.tmpfsPath, nil
}

func (t *tmpfsIsolator) Teardown(ctx context.Context, preserveChanges bool) error {
	if !t.setupDone {
		return nil
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Unmount tmpfs (all changes are lost)
	cmd := exec.CommandContext(ctx, "umount", t.tmpfsPath)
	_ = cmd.Run()

	return os.RemoveAll(t.tmpfsPath)
}

func (t *tmpfsIsolator) Changes(ctx context.Context) ([]FileChange, error) {
	if !t.setupDone {
		return nil, fmt.Errorf("tmpfs not set up")
	}

	return diffDirectories(t.cfg.OriginalPath, t.tmpfsPath)
}

func (t *tmpfsIsolator) Sync(ctx context.Context, patterns, excludePatterns []string) error {
	if !t.setupDone {
		return fmt.Errorf("tmpfs not set up")
	}

	changes, err := t.Changes(ctx)
	if err != nil {
		return err
	}

	return syncChanges(t.tmpfsPath, t.cfg.OriginalPath, changes, patterns, excludePatterns)
}

func (t *tmpfsIsolator) IsolatedPath() string {
	return t.tmpfsPath
}

func (t *tmpfsIsolator) OriginalPath() string {
	return t.cfg.OriginalPath
}

// Helper functions

// copyDir recursively copies a directory.
// SECURITY: Uses os.Root (Go 1.24+) for traversal-resistant file operations.
// This provides OS-level guarantees against symlink escape attacks.
// Uses fs.WalkDir with os.Root.FS() for efficient, secure directory traversal.
// See: https://go.dev/blog/osroot
func copyDir(ctx context.Context, src, dst string) error {
	// Open source as a root for traversal-resistant access
	srcRoot, err := os.OpenRoot(src)
	if err != nil {
		return fmt.Errorf("open source root: %w", err)
	}
	defer srcRoot.Close()

	// Use fs.WalkDir with os.Root.FS() for efficient, secure traversal
	// This is more efficient than filepath.Walk as it doesn't Lstat every file
	srcFS := srcRoot.FS()

	return fs.WalkDir(srcFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Check context
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip the root directory itself
		if path == "." {
			return nil
		}

		dstPath := filepath.Join(dst, path)

		// Get file info for mode
		info, err := d.Info()
		if err != nil {
			return err
		}

		// SECURITY: Skip symlinks entirely
		// os.Root prevents following symlinks outside the root during operations,
		// but copying symlinks is still risky. Safer to skip them.
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		if d.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		// Use os.Root to safely open the source file
		return copyFileWithRoot(srcRoot, path, dstPath, info.Mode())
	})
}

// copyFileWithRoot copies a file using os.Root for traversal-resistant source access.
func copyFileWithRoot(srcRoot *os.Root, relPath, dstPath string, mode os.FileMode) error {
	// Open source file through root (traversal-resistant)
	srcFile, err := srcRoot.Open(relPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
		return err
	}

	// Create destination file
	dstFile, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}


// copyFile copies a single file.
func copyFile(src, dst string, mode os.FileMode) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// diffDirectories compares two directories and returns changes.
// SECURITY: Uses os.Root (Go 1.24+) for traversal-resistant file operations.
func diffDirectories(original, modified string) ([]FileChange, error) {
	// Open both directories as roots for traversal-resistant access
	origRoot, err := os.OpenRoot(original)
	if err != nil {
		return nil, fmt.Errorf("open original root: %w", err)
	}
	defer origRoot.Close()

	modRoot, err := os.OpenRoot(modified)
	if err != nil {
		return nil, fmt.Errorf("open modified root: %w", err)
	}
	defer modRoot.Close()

	var changes []FileChange
	seen := make(map[string]bool)

	// Walk modified directory to find added/modified files
	modFS := modRoot.FS()
	err = fs.WalkDir(modFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}

		// Skip .git directory - these are git metadata, not user code changes.
		// Syncing .git changes could corrupt the git state and is not meaningful for review.
		if path == ".git" || strings.HasPrefix(path, ".git/") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		seen[path] = true

		info, err := d.Info()
		if err != nil {
			return err
		}

		// Check if file exists in original using os.Root
		origInfo, err := origRoot.Stat(path)

		if os.IsNotExist(err) {
			changes = append(changes, FileChange{
				Path:    path,
				Type:    "added",
				Size:    info.Size(),
				ModTime: info.ModTime(),
			})
		} else if err == nil && !info.IsDir() {
			// Check if modified by comparing content
			// Size difference is a quick check, then compare content
			if info.Size() != origInfo.Size() || !filesEqualWithRoots(origRoot, modRoot, path) {
				changes = append(changes, FileChange{
					Path:    path,
					Type:    "modified",
					Size:    info.Size(),
					ModTime: info.ModTime(),
				})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Walk original directory to find deleted files
	origFS := origRoot.FS()
	err = fs.WalkDir(origFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return nil
		}

		// Skip .git directory
		if path == ".git" || strings.HasPrefix(path, ".git/") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if !seen[path] {
			changes = append(changes, FileChange{
				Path: path,
				Type: "deleted",
			})
		}
		return nil
	})

	return changes, err
}

// filesEqualWithRoots compares two files using os.Root for traversal-resistant access.
func filesEqualWithRoots(root1, root2 *os.Root, path string) bool {
	// Use os.Root.FS() which implements fs.ReadFileFS
	fsys1 := root1.FS().(fs.ReadFileFS)
	fsys2 := root2.FS().(fs.ReadFileFS)

	content1, err := fsys1.ReadFile(path)
	if err != nil {
		return false
	}
	content2, err := fsys2.ReadFile(path)
	if err != nil {
		return false
	}
	return string(content1) == string(content2)
}

// parseGitDiff parses git diff --name-status output.
func parseGitDiff(output string) ([]FileChange, error) {
	var changes []FileChange

	for line := range strings.SplitSeq(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		status := parts[0]
		path := parts[1]

		var changeType string
		switch status[0] {
		case 'A':
			changeType = "added"
		case 'M':
			changeType = "modified"
		case 'D':
			changeType = "deleted"
		case 'R':
			changeType = "renamed"
		default:
			changeType = "modified"
		}

		change := FileChange{
			Path: path,
			Type: changeType,
		}

		if changeType == "renamed" && len(parts) >= 3 {
			change.OldPath = parts[1]
			change.Path = parts[2]
		}

		changes = append(changes, change)
	}

	return changes, nil
}

// syncChanges copies changes from src to dst, respecting patterns.
// SECURITY: Uses os.Root (Go 1.24+) for traversal-resistant file operations.
// This provides OS-level guarantees against symlink escape attacks.
// See: https://go.dev/blog/osroot
func syncChanges(src, dst string, changes []FileChange, patterns, excludePatterns []string) error {
	// Open roots for traversal-resistant file access
	// os.Root ensures symlinks cannot escape the directory boundary
	srcRoot, err := os.OpenRoot(src)
	if err != nil {
		return fmt.Errorf("open source root: %w", err)
	}
	defer srcRoot.Close()

	dstRoot, err := os.OpenRoot(dst)
	if err != nil {
		return fmt.Errorf("open destination root: %w", err)
	}
	defer dstRoot.Close()

	for _, change := range changes {
		// Check patterns
		if len(patterns) > 0 && !matchesAnyPattern(change.Path, patterns) {
			continue
		}
		if matchesAnyPattern(change.Path, excludePatterns) {
			continue
		}

		// SECURITY: Validate path doesn't contain traversal sequences
		// os.Root handles symlink traversal, but we still reject explicit ".."
		if strings.Contains(change.Path, "..") {
			continue // Skip paths with traversal
		}

		switch change.Type {
		case "deleted":
			// Use os.Root for safe removal - prevents symlink escape
			if err := dstRoot.Remove(change.Path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("delete %s: %w", change.Path, err)
			}
		case "added", "modified":
			// Use os.Root.Lstat for traversal-resistant stat
			srcInfo, err := srcRoot.Lstat(change.Path)
			if err != nil {
				// File may have been deleted since diff - skip
				continue
			}

			// SECURITY: Skip symlinks entirely when syncing
			// os.Root prevents following symlinks outside the root during open,
			// but syncing symlinks is still risky. Safer to skip them.
			if srcInfo.Mode()&os.ModeSymlink != 0 {
				continue
			}

			if srcInfo.IsDir() {
				// Use Perm() to get just the permission bits, not the full mode
				if err := dstRoot.Mkdir(change.Path, srcInfo.Mode().Perm()); err != nil && !os.IsExist(err) {
					return fmt.Errorf("mkdir %s: %w", change.Path, err)
				}
			} else {
				// Ensure parent directory exists
				parentDir := filepath.Dir(change.Path)
				if parentDir != "." && parentDir != "" {
					if err := mkdirAllWithRoot(dstRoot, parentDir, 0755); err != nil {
						return fmt.Errorf("mkdir parent of %s: %w", change.Path, err)
					}
				}

				// Copy file using os.Root for both read and write
				if err := copyFileWithRoots(srcRoot, dstRoot, change.Path, srcInfo.Mode()); err != nil {
					return fmt.Errorf("copy %s: %w", change.Path, err)
				}
			}
		}
	}

	return nil
}

// mkdirAllWithRoot creates a directory and all parent directories using os.Root.
// This is a traversal-resistant version of os.MkdirAll.
func mkdirAllWithRoot(root *os.Root, path string, perm os.FileMode) error {
	// Split path into components and create each directory
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	current := ""

	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if current == "" {
			current = part
		} else {
			current = filepath.Join(current, part)
		}

		if err := root.Mkdir(current, perm); err != nil && !os.IsExist(err) {
			return err
		}
	}
	return nil
}

// copyFileWithRoots copies a file using os.Root for traversal-resistant access.
// This ensures neither read nor write can escape the respective directory roots.
func copyFileWithRoots(srcRoot, dstRoot *os.Root, path string, mode os.FileMode) error {
	// Open source file through root (traversal-resistant)
	srcFile, err := srcRoot.Open(path)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Create destination file through root (traversal-resistant)
	dstFile, err := dstRoot.Create(path)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Copy contents
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	// Set permissions
	return dstFile.Chmod(mode)
}

// matchesAnyPattern checks if path matches any glob pattern.
func matchesAnyPattern(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		// Also try matching against just the filename
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
	}
	return false
}
