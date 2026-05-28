package providers

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/temporalio/deputy/internal/auth"
	"github.com/temporalio/deputy/internal/gitutil"
	"github.com/temporalio/deputy/internal/repository"
	"github.com/temporalio/deputy/internal/repository/workspace"
	"github.com/temporalio/deputy/internal/targets"
)

func init() {
	targets.RegisterProvider(localGitProvider{})
	targets.RegisterProvider(localDirProvider{})
	targets.RegisterProvider(containerImageProvider{})
	targets.RegisterProvider(remoteGitProvider{})
	targets.RegisterProvider(vmImageProvider{})
}

const (
	priorityLocalGit  = 100
	priorityLocalDir  = 50
	priorityRemoteGit = 10
)

// localGitProvider implements [targets.Provider] for local Git repositories.
type localGitProvider struct{}

func (localGitProvider) Priority() int { return priorityLocalGit }

// Detect returns true if the target path exists and is a Git repository.
func (localGitProvider) Detect(_ context.Context, target string) bool {
	path := targetPath(target)
	if path == "" {
		return false
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		return false
	}
	if _, err := os.Stat(filepath.Join(path, ".git")); err == nil {
		return true
	}
	if _, err := git.PlainOpen(path); err == nil {
		return true
	}
	return false
}

// Open materializes a local Git repository target.
func (localGitProvider) Open(ctx context.Context, target string, opts map[string]string) (targets.Materialized, error) {
	path := targetPath(target)
	if path == "" {
		return targets.Materialized{}, fmt.Errorf("git target %q not found", target)
	}
	src, err := repository.Open(path)
	if err != nil {
		return targets.Materialized{}, err
	}
	mat := targets.Materialized{
		FS:   src.Workspace(),
		Path: src.Workspace().RootPath(),
		Meta: targets.Descriptor{
			Kind:    targets.KindGit,
			Target:  target,
			Options: opts,
		},
		Data: src,
		Cleanup: func() {
			_ = src.Close() // best-effort resource cleanup
		},
	}
	return mat, nil
}

// localDirProvider implements [targets.Provider] for local directories.
type localDirProvider struct{}

func (localDirProvider) Priority() int { return priorityLocalDir }

// Detect returns true if the target path exists and is a directory.
func (localDirProvider) Detect(_ context.Context, target string) bool {
	path := targetPath(target)
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// Open materializes a local directory target.
func (localDirProvider) Open(ctx context.Context, target string, opts map[string]string) (targets.Materialized, error) {
	path := targetPath(target)
	if path == "" {
		return targets.Materialized{}, fmt.Errorf("directory %q not found", target)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return targets.Materialized{}, err
	}
	ws, err := workspace.NewDir(abs)
	if err != nil {
		return targets.Materialized{}, err
	}
	return targets.Materialized{
		FS:   ws,
		Path: abs,
		Meta: targets.Descriptor{Kind: targets.KindDir, Target: target, Options: opts},
		Data: ws,
		Cleanup: func() {
			_ = ws.Close()
		},
	}, nil
}

// remoteGitProvider implements [targets.Provider] for remote Git repositories.
type remoteGitProvider struct{}

func (remoteGitProvider) Priority() int { return priorityRemoteGit }

// Detect returns true if the target looks like a remote Git URL.
func (remoteGitProvider) Detect(_ context.Context, target string) bool {
	if target == "" {
		return false
	}
	if _, err := os.Stat(target); err == nil {
		return false
	}
	if looksLikeRemoteURL(target) {
		return true
	}
	return gitutil.ToHTTPSGitURL(target) != ""
}

// Open materializes a remote Git repository target by cloning it.
func (remoteGitProvider) Open(ctx context.Context, target string, opts map[string]string) (targets.Materialized, error) {
	ref := ""
	if opts != nil {
		ref = opts["ref"]
	}
	urlStr := target
	if !looksLikeRemoteURL(urlStr) {
		if converted := gitutil.ToHTTPSGitURL(target); converted != "" {
			urlStr = converted
		}
	}
	// Use the unified auth package for secure, host-aware credential resolution
	gitAuth, _ := auth.GitAuthForURL(ctx, urlStr)
	refName, err := gitutil.ResolveReferenceName(ctx, urlStr, gitAuth, ref)
	if err == nil && refName.String() != "" {
		ref = refName.String()
	}
	cloneOpts := &git.CloneOptions{
		URL:          urlStr,
		Depth:        1,
		SingleBranch: true,
		Tags:         git.NoTags,
		Auth:         gitAuth,
	}
	if refName.String() != "" {
		cloneOpts.ReferenceName = refName
	}
	src, err := repository.Clone(ctx, cloneOpts, false)
	if err != nil && cloneOpts.ReferenceName != "" {
		cloneOpts.ReferenceName = ""
		src, err = repository.Clone(ctx, cloneOpts, false)
	}
	if err != nil {
		return targets.Materialized{}, fmt.Errorf("clone %s: %w", urlStr, err)
	}
	prov := map[string]string{
		"origin": urlStr,
		"cloned": "true",
	}
	if ref != "" {
		prov["ref"] = ref
	}
	mat := targets.Materialized{
		FS:   src.Workspace(),
		Path: src.Workspace().RootPath(),
		Meta: targets.Descriptor{
			Kind:       targets.KindGit,
			Target:     target,
			Options:    opts,
			Provenance: prov,
		},
		Data: src,
		Cleanup: func() {
			_ = src.Close() // best-effort resource cleanup
		},
	}
	return mat, nil
}

// targetPath returns the absolute path of the target if it exists locally.
func targetPath(target string) string {
	if target == "" {
		return ""
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return ""
	}
	return abs
}

// looksLikeRemoteURL returns true if the string appears to be a remote URL or SSH path.
func looksLikeRemoteURL(s string) bool {
	if strings.HasPrefix(s, "git@") {
		return true
	}
	if strings.Contains(s, "://") {
		return true
	}
	if strings.Count(s, "/") >= 2 && !strings.ContainsRune(s, os.PathSeparator) {
		if _, err := url.Parse("https://" + s); err == nil {
			return true
		}
	}
	return false
}
