package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/spf13/cobra"
)

func TestSBOMShowContextFlag(t *testing.T) {
	repo := initSBOMTestRepo(t)

	stderr := runSBOMCommand(t, repo, filepath.Join(repo, "sbom-no-context.json"), false)
	if strings.Contains(stderr, "Context") {
		t.Fatalf("expected no context banner when flag unset; stderr=%q", stderr)
	}

	stderr = runSBOMCommand(t, repo, filepath.Join(repo, "sbom-context.json"), true)
	if !strings.Contains(stderr, "Context") {
		t.Fatalf("expected context header when flag set; stderr=%q", stderr)
	}
	if !strings.Contains(stderr, "Repo:") || !strings.Contains(stderr, "Commit:") {
		t.Fatalf("expected repo and commit lines in context output; stderr=%q", stderr)
	}
}

func runSBOMCommand(t *testing.T, repo, outPath string, showContext bool) string {
	t.Helper()
	root := &cobra.Command{Use: "deputy"}
	root.SetContext(t.Context())
	root.SetOut(io.Discard)
	var stderr bytes.Buffer
	root.SetErr(&stderr)
	AddSBOMCommand(root)

	args := []string{"sbom", repo, "--format", "protobom-json", "--output", outPath}
	if showContext {
		args = append(args, "--show-context")
	}
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("execute sbom: %v", err)
	}
	return stderr.String()
}

func initSBOMTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.24"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}"), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if _, err := wt.Add("go.mod"); err != nil {
		t.Fatalf("add go.mod: %v", err)
	}
	if _, err := wt.Add("main.go"); err != nil {
		t.Fatalf("add main.go: %v", err)
	}
	if _, err := wt.Commit("initial", &git.CommitOptions{Author: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()}}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return dir
}
