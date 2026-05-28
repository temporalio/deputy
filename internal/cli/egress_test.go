package cli

import (
	"fmt"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/temporalio/deputy/internal/config"
	"github.com/temporalio/deputy/internal/gitutil"
	"github.com/temporalio/deputy/internal/network"
)

func TestLocalEgressAllowlist_LoopbackGitHTTP(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cgi-based git-http-backend test is not supported on Windows")
	}

	gitBackend, err := gitHTTPBackendPath()
	if err != nil {
		t.Skipf("git-http-backend not available: %v", err)
	}

	tmpDir := t.TempDir()
	workDir := filepath.Join(tmpDir, "work")
	repo, err := git.PlainInit(workDir, false)
	if err != nil {
		t.Fatalf("init repo: %v", err)
	}

	readmePath := filepath.Join(workDir, "README.md")
	if err := os.WriteFile(readmePath, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write readme: %v", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if _, err := wt.Add("README.md"); err != nil {
		t.Fatalf("add readme: %v", err)
	}
	if _, err := wt.Commit("init", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@example.com",
			When:  time.Now(),
		},
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}

	projectRoot := filepath.Join(tmpDir, "projects")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bareRepo := filepath.Join(projectRoot, "repo.git")
	if _, err := git.PlainClone(bareRepo, true, &git.CloneOptions{URL: workDir}); err != nil {
		t.Fatalf("create bare repo: %v", err)
	}

	handler := &cgi.Handler{
		Path: gitBackend,
		Env: []string{
			"GIT_HTTP_EXPORT_ALL=true",
			fmt.Sprintf("GIT_PROJECT_ROOT=%s", projectRoot),
		},
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	resetNetworkDefaults := func() {
		network.SetDefaultSafeDialerOptions()
		gitutil.InstallSafeGitTransport()
	}
	resetNetworkDefaults()
	t.Cleanup(resetNetworkDefaults)

	blockedPath := filepath.Join(tmpDir, "clone-blocked")
	if _, err := git.PlainClone(blockedPath, false, &git.CloneOptions{URL: server.URL + "/repo.git"}); err == nil {
		t.Fatalf("expected loopback clone to be blocked without allowlist")
	}

	applyLocalEgressConfig(&config.Config{
		Egress: &config.EgressConfig{
			AllowLoopback: true,
		},
	})

	allowedPath := filepath.Join(tmpDir, "clone-allowed")
	if _, err := git.PlainClone(allowedPath, false, &git.CloneOptions{URL: server.URL + "/repo.git"}); err != nil {
		t.Fatalf("expected clone to succeed with allowlist: %v", err)
	}
}

func gitHTTPBackendPath() (string, error) {
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", err
	}

	out, err := exec.Command(gitPath, "--exec-path").Output()
	if err != nil {
		return "", err
	}

	execPath := strings.TrimSpace(string(out))
	if execPath == "" {
		return "", fmt.Errorf("empty git exec-path")
	}

	backend := filepath.Join(execPath, "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		return "", err
	}

	return backend, nil
}
