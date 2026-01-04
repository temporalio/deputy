package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/gitutil"
	gitx "github.com/picatz/deputy/internal/gitutil"
	"github.com/picatz/deputy/internal/repository"
	"github.com/picatz/deputy/internal/repository/workspace"
	"github.com/picatz/deputy/internal/targets"
	_ "github.com/picatz/deputy/internal/targets/providers"
)

type resolvedTarget struct {
	mat           targets.Materialized
	kind          targets.Kind
	workspace     workspace.FS
	localRepoPath string
	displayPath   string
	ref           string
	cloned        bool
	cleanup       func()
}

// resolveTarget resolves the input target string to a materialized target with
// local filesystem access. Returns workspace, paths, and cleanup function.
func resolveTarget(ctx context.Context, targetInput, ref string) (*resolvedTarget, error) {
	if targetInput = strings.TrimSpace(targetInput); targetInput == "" {
		wd, err := osGetwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get current directory: %w", err)
		}
		targetInput = wd
	}

	mOpts := map[string]string{}
	if ref != "" {
		mOpts["ref"] = ref
	}

	mat, err := targets.Open(ctx, targetInput, mOpts)
	if err != nil {
		if errors.Is(err, targets.ErrNoProvider) {
			return nil, fmt.Errorf("could not interpret target %q as local path or remote Git URL", targetInput)
		}
		return nil, err
	}

	cleanup := func() {}
	if mat.Cleanup != nil {
		cleanup = mat.Cleanup
	}

	var ws workspace.FS
	switch src := mat.Data.(type) {
	case *repository.Source:
		ws = src.Workspace
	case workspace.FS:
		ws = src
	}

	localRepoPath := mat.Path
	if localRepoPath == "" {
		if src, ok := mat.Data.(interface{ RootPath() string }); ok {
			localRepoPath = src.RootPath()
		}
	}
	if localRepoPath == "" {
		cleanup()
		return nil, fmt.Errorf("target %q did not provide a local filesystem path", targetInput)
	}
	if abs, err := filepath.Abs(localRepoPath); err == nil {
		localRepoPath = abs
	}

	displayPath := targetInput
	if mat.Meta.Target != "" {
		displayPath = mat.Meta.Target
	}
	if pRef := mat.Meta.Provenance["ref"]; pRef != "" {
		ref = pRef
	}
	cloned := strings.EqualFold(mat.Meta.Provenance["cloned"], "true")

	return &resolvedTarget{
		mat:           mat,
		kind:          mat.Meta.Kind,
		workspace:     ws,
		localRepoPath: localRepoPath,
		displayPath:   displayPath,
		ref:           ref,
		cloned:        cloned,
		cleanup:       cleanup,
	}, nil
}

// refOrHEAD returns RefHEAD if the input reference is empty, otherwise returns the input.
func refOrHEAD(r string) string {
	if strings.TrimSpace(r) == "" {
		return gitx.RefHEAD
	}
	return r
}

// getRepoMetadata attempts to resolve the commit hash and origin URL for the given repository path and reference.
func getRepoMetadata(localRepoPath, ref string) (string, string) {
	commitHash := ""
	originURL := ""

	repo, err := git.PlainOpen(localRepoPath)
	if err != nil {
		return commitHash, originURL
	}

	if h, err := gitx.ResolveRevisionEnhanced(repo, refOrHEAD(ref)); err == nil && h != nil {
		commitHash = h.String()
	} else if headRef, err := repo.Head(); err == nil {
		commitHash = headRef.Hash().String()
	}

	if r, err := repo.Remote("origin"); err == nil && r != nil && r.Config() != nil && len(r.Config().URLs) > 0 {
		u := strings.TrimSpace(r.Config().URLs[0])
		if u != "" {
			switch {
			case strings.HasPrefix(u, "git@github.com:"):
				p := strings.TrimPrefix(u, "git@github.com:")
				if !strings.HasSuffix(p, ".git") {
					p += ".git"
				}
				originURL = "https://github.com/" + p
			case strings.HasPrefix(u, "ssh://git@github.com/"):
				p := strings.TrimPrefix(u, "ssh://git@github.com/")
				if !strings.HasSuffix(p, ".git") {
					p += ".git"
				}
				originURL = "https://github.com/" + p
			default:
				originURL = u
				if n := gitutil.ToHTTPSGitURL(u); n != "" {
					originURL = n
				}
			}
		}
	}

	return commitHash, originURL
}

type directModuleInfo struct {
	goDirect map[string]bool
	resolver ManifestResolver
}

// resolveDirectModules determines direct Go modules and manifest resolver based on
// the effective reference and workspace/repository state.
func resolveDirectModules(localRepoPath, effRef string, ws workspace.FS) directModuleInfo {
	goDirect := map[string]bool{"stdlib": true}
	var resolver ManifestResolver = WorkspaceManifestResolver{ws: ws}

	if strings.EqualFold(effRef, "HEAD") || strings.EqualFold(effRef, "HEAD~0") {
		if ws != nil {
			goDirect = compare.CollectGoDirectModulesFromWorkspace(ws)
		}
		return directModuleInfo{goDirect: goDirect, resolver: resolver}
	}

	repo, err := git.PlainOpen(localRepoPath)
	if err != nil {
		return directModuleInfo{goDirect: goDirect, resolver: resolver}
	}

	h, err := gitx.ResolveRevisionEnhanced(repo, effRef)
	if err != nil || h == nil {
		return directModuleInfo{goDirect: goDirect, resolver: resolver}
	}

	if direct, derr := compare.CollectGoDirectModulesFromCommit(repo, *h); derr == nil {
		goDirect = direct
	}
	resolver = GitManifestResolver{repo: repo, hash: *h}

	return directModuleInfo{goDirect: goDirect, resolver: resolver}
}

// osGetwd is a test seam for os.Getwd.
var osGetwd = os.Getwd
