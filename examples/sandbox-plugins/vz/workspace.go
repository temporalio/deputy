//go:build darwin && arm64

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
)

// workspaceConfig holds workspace configuration for the VM.
type workspaceConfig struct {
	// Mode determines how the workspace is mounted
	mode sandboxv1.WorkspaceIsolationMode

	// Direct mode: single path mounted as "workspace"
	directPath string

	// Overlay mode: base (RO) + upper (RW) merged via overlayfs in guest
	basePath  string // Original workspace (read-only)
	upperPath string // Changes directory (read-write)
	tempDir   string // Temp dir for upper layer

	// Git worktree mode: worktree path and branch name
	worktreePath string // Path to the git worktree
	branchName   string // Branch name for the worktree

	// Whether to keep the upper layer after execution
	preserveChanges bool
}

// newWorkspaceConfig creates workspace configuration based on the sandbox config.
func newWorkspaceConfig(workspaceDir string, config *sandboxv1.SandboxConfig) (*workspaceConfig, error) {
	if workspaceDir == "" {
		return nil, nil // No workspace requested
	}

	// Verify workspace exists
	info, err := os.Stat(workspaceDir)
	if err != nil {
		return nil, fmt.Errorf("workspace not found: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("workspace is not a directory: %s", workspaceDir)
	}

	// Determine isolation mode
	isolationMode := config.GetWorkspaceIsolation()
	if isolationMode == sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_UNSPECIFIED {
		isolationMode = sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_DIRECT
	}

	wc := &workspaceConfig{
		mode: isolationMode,
	}

	switch isolationMode {
	case sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_DIRECT:
		wc.directPath = workspaceDir

	case sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_OVERLAY:
		wc.basePath = workspaceDir

		// Create temp directory for the upper layer
		tempDir := filepath.Join(os.TempDir(), "deputy-vz-workspace",
			fmt.Sprintf("overlay-%d-%d", time.Now().UnixNano(), os.Getpid()))
		if err := os.MkdirAll(tempDir, 0755); err != nil {
			return nil, fmt.Errorf("create overlay temp dir: %w", err)
		}
		wc.upperPath = tempDir
		wc.tempDir = tempDir

		// Check if we should preserve changes
		isolationConfig := config.GetWorkspaceIsolationConfig()
		if isolationConfig != nil {
			wc.preserveChanges = isolationConfig.GetPreserveAfterExecution() || config.GetReviewBeforeCommit()
		} else if config.GetReviewBeforeCommit() {
			wc.preserveChanges = true
		}

	case sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT:
		// Snapshot mode: copy workspace to temp directory
		tempDir := filepath.Join(os.TempDir(), "deputy-vz-workspace",
			fmt.Sprintf("snapshot-%d-%d", time.Now().UnixNano(), os.Getpid()))
		if err := os.MkdirAll(tempDir, 0755); err != nil {
			return nil, fmt.Errorf("create snapshot dir: %w", err)
		}

		// Copy workspace to snapshot (using rsync-like copy)
		if err := copyDir(workspaceDir, tempDir); err != nil {
			os.RemoveAll(tempDir)
			return nil, fmt.Errorf("create workspace snapshot: %w", err)
		}

		wc.directPath = tempDir
		wc.tempDir = tempDir
		wc.basePath = workspaceDir // Keep original for diff comparison

		isolationConfig := config.GetWorkspaceIsolationConfig()
		if isolationConfig != nil {
			wc.preserveChanges = isolationConfig.GetPreserveAfterExecution() || config.GetReviewBeforeCommit()
		} else if config.GetReviewBeforeCommit() {
			wc.preserveChanges = true
		}

	case sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_GIT_WORKTREE:
		// Git worktree mode: create a worktree for isolated git operations
		// This allows the AI agent to make changes on a separate branch
		// that can be reviewed before merging to the main branch.

		// Verify the workspace is a git repository
		gitDir := filepath.Join(workspaceDir, ".git")
		if _, err := os.Stat(gitDir); os.IsNotExist(err) {
			return nil, fmt.Errorf("git worktree mode requires a git repository: %s is not a git repo", workspaceDir)
		}

		// Get branch name from config or generate one
		isolationConfig := config.GetWorkspaceIsolationConfig()
		branchName := ""
		if isolationConfig != nil {
			branchName = isolationConfig.GetWorktreeBranch()
		}
		if branchName == "" {
			branchName = fmt.Sprintf("deputy-sandbox-%d", time.Now().UnixNano())
		}

		// Create worktree directory
		worktreeDir := filepath.Join(os.TempDir(), "deputy-vz-worktree",
			fmt.Sprintf("wt-%d-%d", time.Now().UnixNano(), os.Getpid()))
		if err := os.MkdirAll(filepath.Dir(worktreeDir), 0755); err != nil {
			return nil, fmt.Errorf("create worktree parent dir: %w", err)
		}

		// Create the git worktree with a new branch
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "git", "worktree", "add", "-b", branchName, worktreeDir)
		cmd.Dir = workspaceDir
		if output, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("create git worktree: %s: %w", string(output), err)
		}

		wc.mode = sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_GIT_WORKTREE
		wc.directPath = worktreeDir // Mount the worktree as the workspace
		wc.worktreePath = worktreeDir
		wc.branchName = branchName
		wc.basePath = workspaceDir // Keep original for cleanup
		wc.tempDir = worktreeDir   // Mark for cleanup

		// Check if we should preserve changes
		if isolationConfig != nil {
			wc.preserveChanges = isolationConfig.GetPreserveAfterExecution() || config.GetReviewBeforeCommit()
		} else if config.GetReviewBeforeCommit() {
			wc.preserveChanges = true
		}

	case sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_TMPFS:
		// Tmpfs mode: overlay with in-memory upper layer
		// The deputy-init handles this - we set up overlay mode and it uses tmpfs
		wc.basePath = workspaceDir
		wc.mode = sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_OVERLAY
		// No tempDir needed - changes go to tmpfs in VM
		wc.preserveChanges = false // Can't preserve tmpfs changes

	default:
		// Fall back to direct mode
		wc.mode = sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_DIRECT
		wc.directPath = workspaceDir
	}

	return wc, nil
}

// IsOverlay returns true if the workspace uses overlay mode.
func (wc *workspaceConfig) IsOverlay() bool {
	return wc != nil && wc.mode == sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_OVERLAY
}

// IsDirect returns true if the workspace uses direct mode.
func (wc *workspaceConfig) IsDirect() bool {
	return wc != nil && wc.mode == sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_DIRECT
}

// IsGitWorktree returns true if the workspace uses git worktree mode.
func (wc *workspaceConfig) IsGitWorktree() bool {
	return wc != nil && wc.mode == sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_GIT_WORKTREE
}

// GetBranchName returns the branch name for git worktree mode.
func (wc *workspaceConfig) GetBranchName() string {
	if wc == nil {
		return ""
	}
	return wc.branchName
}

// GetWorktreePath returns the worktree path for git worktree mode.
func (wc *workspaceConfig) GetWorktreePath() string {
	if wc == nil {
		return ""
	}
	return wc.worktreePath
}

// GetChangesPath returns the path where changes are stored (for overlay/snapshot modes).
func (wc *workspaceConfig) GetChangesPath() string {
	if wc == nil {
		return ""
	}
	if wc.IsOverlay() {
		return wc.upperPath
	}
	// For snapshot mode, changes are in the snapshot directory
	if wc.tempDir != "" && wc.directPath != "" {
		return wc.directPath
	}
	return ""
}

// GetOriginalPath returns the original workspace path (for diff comparison).
func (wc *workspaceConfig) GetOriginalPath() string {
	if wc == nil {
		return ""
	}
	if wc.basePath != "" {
		return wc.basePath
	}
	return wc.directPath
}

// fixGitFile restores the .git file to point to the correct host path.
// The VM modifies the .git file to point to /mnt/workspace-git/worktrees/...
// which doesn't exist on the host. This function restores it to the correct path.
func (wc *workspaceConfig) fixGitFile() error {
	if wc == nil || wc.worktreePath == "" || wc.basePath == "" {
		return nil
	}

	gitFilePath := filepath.Join(wc.worktreePath, ".git")
	content, err := os.ReadFile(gitFilePath)
	if err != nil {
		return fmt.Errorf("read .git file: %w", err)
	}

	contentStr := strings.TrimSpace(string(content))
	if !strings.HasPrefix(contentStr, "gitdir:") {
		// Not a gitdir file, nothing to fix
		return nil
	}

	// Check if it points to the VM path
	if !strings.Contains(contentStr, "/mnt/workspace-git/") {
		// Already correct
		return nil
	}

	// Extract the worktree name from the VM path
	// Format: "gitdir: /mnt/workspace-git/worktrees/wt-name"
	parts := strings.Split(contentStr, "/worktrees/")
	if len(parts) != 2 {
		return fmt.Errorf("unexpected .git file format: %s", contentStr)
	}
	worktreeName := strings.TrimSpace(parts[1])

	// Reconstruct the correct host path
	correctPath := fmt.Sprintf("gitdir: %s/.git/worktrees/%s", wc.basePath, worktreeName)

	// Write the corrected .git file
	if err := os.WriteFile(gitFilePath, []byte(correctPath+"\n"), 0644); err != nil {
		return fmt.Errorf("write .git file: %w", err)
	}

	slog.Debug("Fixed .git file", "worktreePath", wc.worktreePath, "correctedGitdir", correctPath)
	return nil
}

// Cleanup removes temporary directories if they exist.
// If preserveChanges is true, this is a no-op.
func (wc *workspaceConfig) Cleanup() error {
	if wc == nil {
		return nil
	}
	if wc.preserveChanges {
		slog.Debug("Cleanup skipped", "reason", "preserveChanges=true")
		return nil
	}
	if wc.tempDir == "" {
		return nil
	}
	slog.Debug("Cleaning up workspace", "tempDir", wc.tempDir, "mode", wc.mode.String())

	// For git worktree mode, clean up the worktree and branch
	if wc.IsGitWorktree() && wc.worktreePath != "" && wc.basePath != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		slog.Debug("Cleaning up git worktree", "worktreePath", wc.worktreePath, "basePath", wc.basePath)

		// Try git worktree remove first
		cmd := exec.CommandContext(ctx, "git", "worktree", "remove", "--force", wc.worktreePath)
		cmd.Dir = wc.basePath
		if err := cmd.Run(); err != nil {
			// If git worktree remove fails (e.g., .git file was modified by VM),
			// fall back to manual removal + prune using safe removal to prevent
			// symlink attacks from a potentially compromised worktree filesystem.
			slog.Debug("git worktree remove failed, falling back to safe manual cleanup", "error", err)
			if removeErr := safeRemoveAll(wc.worktreePath); removeErr != nil {
				slog.Warn("Failed to remove worktree directory", "path", wc.worktreePath, "error", removeErr)
			}
			// Run git worktree prune to clean up the worktree entry
			pruneCmd := exec.CommandContext(ctx, "git", "worktree", "prune")
			pruneCmd.Dir = wc.basePath
			_ = pruneCmd.Run() // Best effort
		}

		// Delete the branch
		if wc.branchName != "" {
			cmd = exec.CommandContext(ctx, "git", "branch", "-D", wc.branchName)
			cmd.Dir = wc.basePath
			_ = cmd.Run() // Best effort - branch may already be deleted or still in use
		}

		return nil
	}

	// For non-worktree temp directories, use safe removal as well
	return safeRemoveAll(wc.tempDir)
}

// safeRemoveAll removes a directory tree safely using os.Root to prevent
// symlink attacks. If the target could be controlled by untrusted code
// (e.g., a VM sandbox), this prevents symlinks from causing deletion of
// files outside the intended directory.
//
// Uses os.Root (Go 1.24+) which provides a rooted filesystem view that
// prevents path traversal via symlinks or .. components.
func safeRemoveAll(dir string) error {
	// First, verify the directory exists and get its absolute path
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("get absolute path: %w", err)
	}

	info, err := os.Lstat(absDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Already gone
		}
		return fmt.Errorf("stat directory: %w", err)
	}

	// If it's a symlink at the top level, just remove the link itself
	if info.Mode()&os.ModeSymlink != 0 {
		return os.Remove(absDir)
	}

	if !info.IsDir() {
		return os.Remove(absDir)
	}

	// Open the directory as a root to get a confined view
	root, err := os.OpenRoot(absDir)
	if err != nil {
		return fmt.Errorf("open root: %w", err)
	}
	defer root.Close()

	// Recursively remove all contents using the rooted view
	if err := safeRemoveContents(root, "."); err != nil {
		return err
	}

	// Finally, remove the now-empty directory itself
	// This is safe because we've already verified it's not a symlink
	return os.Remove(absDir)
}

// safeRemoveContents recursively removes directory contents using os.Root.
// The path is relative to the root and will not escape the rooted directory.
func safeRemoveContents(root *os.Root, path string) error {
	// Open the directory within the root
	dir, err := root.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}

	entries, err := dir.Readdirnames(-1)
	dir.Close()
	if err != nil {
		return fmt.Errorf("read dir %s: %w", path, err)
	}

	for _, entry := range entries {
		entryPath := filepath.Join(path, entry)

		// Use Lstat to check the entry type without following symlinks
		info, err := root.Lstat(entryPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue // Already removed
			}
			return fmt.Errorf("lstat %s: %w", entryPath, err)
		}

		// For symlinks, just remove the link
		if info.Mode()&os.ModeSymlink != 0 {
			if err := root.Remove(entryPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove symlink %s: %w", entryPath, err)
			}
			continue
		}

		// For directories, recurse first
		if info.IsDir() {
			if err := safeRemoveContents(root, entryPath); err != nil {
				return err
			}
		}

		// Remove the entry (file or now-empty directory)
		if err := root.Remove(entryPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", entryPath, err)
		}
	}

	return nil
}

// SyncChangesToOriginal copies changes from the worktree back to the original repo.
// For git worktree mode, this copies the changed files (but does NOT commit).
// The user can then review and commit the changes themselves.
func (wc *workspaceConfig) SyncChangesToOriginal() error {
	if wc == nil {
		return nil
	}

	if !wc.IsGitWorktree() {
		// For non-git modes, use simple file copy
		return wc.syncNonGitChanges()
	}

	// For git worktree mode, get the list of changed files and copy them
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Fix the .git file if it was modified by the VM
	// The VM changes it to point to /mnt/workspace-git/... which doesn't exist on host
	if err := wc.fixGitFile(); err != nil {
		slog.Warn("Failed to fix .git file, continuing anyway", "error", err)
	}

	// Get list of changed files in the worktree
	cmd := exec.CommandContext(ctx, "git", "diff", "--name-only", "HEAD")
	cmd.Dir = wc.worktreePath
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("get changed files: %w", err)
	}

	// Also get untracked files
	cmd = exec.CommandContext(ctx, "git", "ls-files", "--others", "--exclude-standard")
	cmd.Dir = wc.worktreePath
	untrackedOutput, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("get untracked files: %w", err)
	}

	// Combine changed and untracked files
	changedFiles := splitLines(string(output))
	untrackedFiles := splitLines(string(untrackedOutput))
	allFiles := append(changedFiles, untrackedFiles...)

	// Copy each changed file to the original repo
	for _, relPath := range allFiles {
		if relPath == "" {
			continue
		}

		srcPath := filepath.Join(wc.worktreePath, relPath)
		dstPath := filepath.Join(wc.basePath, relPath)

		// Check if file was deleted
		if _, err := os.Stat(srcPath); os.IsNotExist(err) {
			// File was deleted - remove from original
			_ = os.Remove(dstPath)
			continue
		}

		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
			return fmt.Errorf("create parent dir for %s: %w", relPath, err)
		}

		// Copy the file
		if err := copyFile(srcPath, dstPath); err != nil {
			return fmt.Errorf("copy %s: %w", relPath, err)
		}
	}

	return nil
}

// syncNonGitChanges syncs changes for overlay/snapshot modes
func (wc *workspaceConfig) syncNonGitChanges() error {
	changesPath := wc.GetChangesPath()
	originalPath := wc.GetOriginalPath()

	if changesPath == "" || originalPath == "" || changesPath == originalPath {
		return nil
	}

	// Walk the changes directory and copy files to original
	return filepath.Walk(changesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == changesPath {
			return nil
		}

		relPath, err := filepath.Rel(changesPath, path)
		if err != nil {
			return err
		}

		dstPath := filepath.Join(originalPath, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		return copyFile(path, dstPath)
	})
}

// GetChangedFiles returns the list of files changed in the workspace.
func (wc *workspaceConfig) GetChangedFiles() ([]string, error) {
	if wc == nil {
		return nil, nil
	}

	if wc.IsGitWorktree() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Get modified files
		cmd := exec.CommandContext(ctx, "git", "diff", "--name-only", "HEAD")
		cmd.Dir = wc.worktreePath
		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("get changed files: %w", err)
		}

		// Get untracked files
		cmd = exec.CommandContext(ctx, "git", "ls-files", "--others", "--exclude-standard")
		cmd.Dir = wc.worktreePath
		untrackedOutput, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("get untracked files: %w", err)
		}

		changed := splitLines(string(output))
		untracked := splitLines(string(untrackedOutput))
		return append(changed, untracked...), nil
	}

	// For overlay/snapshot modes, compare directories
	// This is a simplified version - just return files in upper/changes dir
	changesPath := wc.GetChangesPath()
	if changesPath == "" {
		return nil, nil
	}

	var files []string
	err := filepath.Walk(changesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == changesPath || info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(changesPath, path)
		if err != nil {
			return err
		}
		files = append(files, relPath)
		return nil
	})

	return files, err
}

// splitLines splits a string into lines, filtering empty lines.
func splitLines(s string) []string {
	var lines []string
	for _, line := range filepath.SplitList(s) {
		if line != "" {
			lines = append(lines, line)
		}
	}
	// filepath.SplitList uses OS path separator, we need newlines
	lines = nil
	for _, line := range splitByNewline(s) {
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// splitByNewline splits a string by newlines
func splitByNewline(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			result = append(result, line)
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}

// copyDir recursively copies a directory.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Calculate destination path
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			return os.MkdirAll(dstPath, info.Mode())
		}

		// Regular file - copy it
		return copyFile(path, dstPath)
	})
}
