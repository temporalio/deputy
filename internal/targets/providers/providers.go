package providers

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/picatz/deputy/internal/repository"
	sbomx "github.com/picatz/deputy/internal/sbom"
	"github.com/picatz/deputy/internal/targets"
)

func init() {
	targets.RegisterProvider(localGitProvider{})
	targets.RegisterProvider(localDirProvider{})
	targets.RegisterProvider(remoteGitProvider{})
}

type localGitProvider struct{}

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
		FS:   src.Workspace,
		Path: src.Workspace.RootPath(),
		Meta: targets.Descriptor{
			Kind:    targets.KindGit,
			Target:  target,
			Options: opts,
		},
		Data: src,
		Cleanup: func() {
			_ = src.Close()
		},
	}
	return mat, nil
}

type localDirProvider struct{}

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

func (localDirProvider) Open(ctx context.Context, target string, opts map[string]string) (targets.Materialized, error) {
	path := targetPath(target)
	if path == "" {
		return targets.Materialized{}, fmt.Errorf("directory %q not found", target)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return targets.Materialized{}, err
	}
	return targets.Materialized{
		FS:   os.DirFS(abs),
		Path: abs,
		Meta: targets.Descriptor{Kind: targets.KindDir, Target: target, Options: opts},
	}, nil
}

type remoteGitProvider struct{}

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
	return sbomx.ToHTTPSGitURL(target) != ""
}

func (remoteGitProvider) Open(ctx context.Context, target string, opts map[string]string) (targets.Materialized, error) {
	ref := ""
	if opts != nil {
		ref = opts["ref"]
	}
	urlStr := target
	if !looksLikeRemoteURL(urlStr) {
		if converted := sbomx.ToHTTPSGitURL(target); converted != "" {
			urlStr = converted
		}
	}
	auth := sbomx.AuthForURL(urlStr)
	refName, err := sbomx.ResolveReferenceName(ctx, urlStr, auth, ref)
	if err == nil && refName.String() != "" {
		ref = refName.String()
	}
	cloneOpts := &git.CloneOptions{
		URL:          urlStr,
		Depth:        1,
		SingleBranch: true,
		Tags:         git.NoTags,
		Auth:         auth,
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
		FS:   src.Workspace,
		Path: src.Workspace.RootPath(),
		Meta: targets.Descriptor{
			Kind:       targets.KindGit,
			Target:     target,
			Options:    opts,
			Provenance: prov,
		},
		Data: src,
		Cleanup: func() {
			_ = src.Close()
		},
	}
	return mat, nil
}

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
