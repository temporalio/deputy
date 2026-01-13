package workspace

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	sandboxv1 "github.com/picatz/deputy/gen/deputy/sandbox/v1"
)

func TestNewReviewSession(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "test.txt"), []byte("original"), 0644)

	isolator, err := New(Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	if _, err := isolator.Setup(ctx); err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer isolator.Teardown(ctx, false)

	session := NewReviewSession(isolator)
	if session == nil {
		t.Fatal("expected non-nil session")
	}
	if session.Result() != ReviewResultPending {
		t.Errorf("expected ReviewResultPending, got %v", session.Result())
	}
}

func TestReviewSessionLoadChanges(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "original.txt"), []byte("original"), 0644)

	isolator, err := New(Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	isolatedPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer isolator.Teardown(ctx, false)

	// Make changes
	os.WriteFile(filepath.Join(isolatedPath, "new.txt"), []byte("new file"), 0644)
	os.WriteFile(filepath.Join(isolatedPath, "original.txt"), []byte("modified"), 0644)

	session := NewReviewSession(isolator)
	if err := session.LoadChanges(ctx); err != nil {
		t.Fatalf("LoadChanges() error = %v", err)
	}

	if !session.HasChanges() {
		t.Error("expected to have changes")
	}

	changes := session.Changes()
	if len(changes) < 2 {
		t.Errorf("expected at least 2 changes, got %d", len(changes))
	}

	// All changes should be selected by default
	if session.SelectedCount() != len(changes) {
		t.Errorf("expected all changes selected, got %d/%d", session.SelectedCount(), len(changes))
	}
}

func TestReviewSessionSummary(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "existing.txt"), []byte("content"), 0644)

	isolator, err := New(Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	isolatedPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer isolator.Teardown(ctx, false)

	// Add new file
	os.WriteFile(filepath.Join(isolatedPath, "new.txt"), []byte("new"), 0644)
	// Modify existing
	os.WriteFile(filepath.Join(isolatedPath, "existing.txt"), []byte("modified"), 0644)

	session := NewReviewSession(isolator)
	if err := session.LoadChanges(ctx); err != nil {
		t.Fatalf("LoadChanges() error = %v", err)
	}

	summary := session.Summary()
	if summary.Total < 2 {
		t.Errorf("expected at least 2 total changes, got %d", summary.Total)
	}
	if summary.Added < 1 {
		t.Errorf("expected at least 1 added file, got %d", summary.Added)
	}
	if summary.Modified < 1 {
		t.Errorf("expected at least 1 modified file, got %d", summary.Modified)
	}
}

func TestReviewSessionSelection(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("content1"), 0644)
	os.WriteFile(filepath.Join(srcDir, "file2.txt"), []byte("content2"), 0644)

	isolator, err := New(Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	isolatedPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer isolator.Teardown(ctx, false)

	// Modify both files
	os.WriteFile(filepath.Join(isolatedPath, "file1.txt"), []byte("modified1"), 0644)
	os.WriteFile(filepath.Join(isolatedPath, "file2.txt"), []byte("modified2"), 0644)

	session := NewReviewSession(isolator)
	if err := session.LoadChanges(ctx); err != nil {
		t.Fatalf("LoadChanges() error = %v", err)
	}

	// Test deselect all
	session.DeselectAll()
	if session.SelectedCount() != 0 {
		t.Errorf("expected 0 selected after DeselectAll, got %d", session.SelectedCount())
	}

	// Test select all
	session.SelectAll()
	if session.SelectedCount() != len(session.Changes()) {
		t.Errorf("expected all selected after SelectAll")
	}

	// Test individual selection
	session.DeselectAll()
	session.SelectPath("file1.txt")
	if !session.IsSelected("file1.txt") {
		t.Error("expected file1.txt to be selected")
	}
	if session.IsSelected("file2.txt") {
		t.Error("expected file2.txt to not be selected")
	}

	// Test toggle
	session.TogglePath("file1.txt")
	if session.IsSelected("file1.txt") {
		t.Error("expected file1.txt to be deselected after toggle")
	}
}

func TestReviewSessionApplySelected(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "keep.txt"), []byte("original"), 0644)
	os.WriteFile(filepath.Join(srcDir, "change.txt"), []byte("original"), 0644)

	isolator, err := New(Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	isolatedPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer isolator.Teardown(ctx, false)

	// Modify both files
	os.WriteFile(filepath.Join(isolatedPath, "keep.txt"), []byte("modified keep"), 0644)
	os.WriteFile(filepath.Join(isolatedPath, "change.txt"), []byte("modified change"), 0644)

	session := NewReviewSession(isolator)
	if err := session.LoadChanges(ctx); err != nil {
		t.Fatalf("LoadChanges() error = %v", err)
	}

	// Only select change.txt
	session.DeselectAll()
	session.SelectPath("change.txt")

	if err := session.ApplySelected(ctx); err != nil {
		t.Fatalf("ApplySelected() error = %v", err)
	}

	if session.Result() != ReviewResultApplySelected {
		t.Errorf("expected ReviewResultApplySelected, got %v", session.Result())
	}

	// Verify change.txt was updated
	content, _ := os.ReadFile(filepath.Join(srcDir, "change.txt"))
	if string(content) != "modified change" {
		t.Errorf("change.txt should be modified, got %q", content)
	}

	// Verify keep.txt was NOT updated
	content, _ = os.ReadFile(filepath.Join(srcDir, "keep.txt"))
	if string(content) != "original" {
		t.Errorf("keep.txt should be original, got %q", content)
	}
}

func TestReviewSessionDiscard(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "test.txt"), []byte("original"), 0644)

	isolator, err := New(Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	isolatedPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	// Modify file
	os.WriteFile(filepath.Join(isolatedPath, "test.txt"), []byte("modified"), 0644)

	session := NewReviewSession(isolator)
	if err := session.Discard(ctx); err != nil {
		t.Fatalf("Discard() error = %v", err)
	}

	if session.Result() != ReviewResultDiscard {
		t.Errorf("expected ReviewResultDiscard, got %v", session.Result())
	}

	// Verify original file unchanged
	content, _ := os.ReadFile(filepath.Join(srcDir, "test.txt"))
	if string(content) != "original" {
		t.Errorf("original file should be unchanged, got %q", content)
	}

	// Verify isolated path cleaned up
	if _, err := os.Stat(isolatedPath); !os.IsNotExist(err) {
		t.Error("isolated path should be cleaned up")
	}
}

func TestReviewSessionPreserve(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "test.txt"), []byte("original"), 0644)

	isolator, err := New(Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	isolatedPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	session := NewReviewSession(isolator)
	preservedPath := session.Preserve()

	if session.Result() != ReviewResultPreserve {
		t.Errorf("expected ReviewResultPreserve, got %v", session.Result())
	}

	if preservedPath != isolatedPath {
		t.Errorf("preserved path = %q, want %q", preservedPath, isolatedPath)
	}

	if session.PreservedPath() != preservedPath {
		t.Errorf("PreservedPath() = %q, want %q", session.PreservedPath(), preservedPath)
	}

	// Path should still exist
	if _, err := os.Stat(preservedPath); os.IsNotExist(err) {
		t.Error("preserved path should still exist")
	}

	// Clean up manually
	os.RemoveAll(preservedPath)
}

func TestReviewSessionPrintChanges(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "existing.txt"), []byte("content"), 0644)

	isolator, err := New(Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	isolatedPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer isolator.Teardown(ctx, false)

	// Make changes
	os.WriteFile(filepath.Join(isolatedPath, "new.txt"), []byte("new"), 0644)
	os.WriteFile(filepath.Join(isolatedPath, "existing.txt"), []byte("modified"), 0644)

	session := NewReviewSession(isolator)
	if err := session.LoadChanges(ctx); err != nil {
		t.Fatalf("LoadChanges() error = %v", err)
	}

	var buf bytes.Buffer
	session.PrintChanges(&buf)

	output := buf.String()
	if output == "" {
		t.Error("expected non-empty output")
	}
	if !bytes.Contains(buf.Bytes(), []byte("new.txt")) {
		t.Error("expected output to contain new.txt")
	}
	if !bytes.Contains(buf.Bytes(), []byte("existing.txt")) {
		t.Error("expected output to contain existing.txt")
	}
	if !bytes.Contains(buf.Bytes(), []byte("Total:")) {
		t.Error("expected output to contain Total:")
	}
}

func TestReviewSessionGetDiff(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "existing.txt"), []byte("line1\nline2\nline3"), 0644)

	isolator, err := New(Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	isolatedPath, err := isolator.Setup(ctx)
	if err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer isolator.Teardown(ctx, false)

	// Add new file
	os.WriteFile(filepath.Join(isolatedPath, "new.txt"), []byte("new content"), 0644)
	// Modify existing
	os.WriteFile(filepath.Join(isolatedPath, "existing.txt"), []byte("line1\nmodified\nline3"), 0644)

	session := NewReviewSession(isolator)
	if err := session.LoadChanges(ctx); err != nil {
		t.Fatalf("LoadChanges() error = %v", err)
	}

	for _, change := range session.Changes() {
		diff, err := session.GetDiff(change)
		if err != nil {
			t.Errorf("GetDiff(%s) error = %v", change.Path, err)
			continue
		}
		if diff == "" {
			t.Errorf("GetDiff(%s) returned empty diff", change.Path)
		}

		// Verify diff contains expected markers
		if change.Type == "added" {
			if !bytes.Contains([]byte(diff), []byte("+")) {
				t.Errorf("added file diff should contain + lines")
			}
		}
	}
}

func TestReviewSessionNoChanges(t *testing.T) {
	srcDir := t.TempDir()
	os.WriteFile(filepath.Join(srcDir, "test.txt"), []byte("content"), 0644)

	isolator, err := New(Config{
		Mode:         sandboxv1.WorkspaceIsolationMode_WORKSPACE_ISOLATION_MODE_SNAPSHOT,
		OriginalPath: srcDir,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.Background()
	if _, err := isolator.Setup(ctx); err != nil {
		t.Fatalf("Setup() error = %v", err)
	}
	defer isolator.Teardown(ctx, false)

	// Don't make any changes

	session := NewReviewSession(isolator)
	if err := session.LoadChanges(ctx); err != nil {
		t.Fatalf("LoadChanges() error = %v", err)
	}

	if session.HasChanges() {
		t.Error("expected no changes")
	}

	var buf bytes.Buffer
	session.PrintChanges(&buf)
	if !bytes.Contains(buf.Bytes(), []byte("No changes detected")) {
		t.Error("expected 'No changes detected' message")
	}
}

func TestDefaultReviewOptions(t *testing.T) {
	opts := DefaultReviewOptions()
	if !opts.ShowDiffs {
		t.Error("expected ShowDiffs to be true")
	}
	if opts.MaxDiffLines != 50 {
		t.Errorf("expected MaxDiffLines=50, got %d", opts.MaxDiffLines)
	}
}

func TestAgentReviewOptions(t *testing.T) {
	opts := AgentReviewOptions()
	if !opts.ShowDiffs {
		t.Error("expected ShowDiffs to be true")
	}
	if opts.MaxDiffLines != 100 {
		t.Errorf("expected MaxDiffLines=100, got %d", opts.MaxDiffLines)
	}
	if !opts.PreserveOnError {
		t.Error("expected PreserveOnError to be true")
	}
}
