package gitutil

import (
	"context"
	"fmt"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/storage/memory"
)

// ToHTTPSGitURL converts a repository reference into an HTTPS URL with a .git suffix.
func ToHTTPSGitURL(ref string) string {
	s := strings.TrimSpace(ref)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		if !strings.HasSuffix(s, ".git") {
			s += ".git"
		}
		return s
	}
	if strings.HasPrefix(s, "github.com/") {
		if !strings.HasSuffix(s, ".git") {
			s += ".git"
		}
		return "https://" + s
	}
	return ""
}

// ResolveReferenceName resolves a user-provided ref to a full ref name.
// It consults the remote to determine a default branch when refStr is empty.
func ResolveReferenceName(ctx context.Context, remoteURL string, auth transport.AuthMethod, refStr string) (plumbing.ReferenceName, error) {
	r := strings.TrimSpace(refStr)
	if r == "" || strings.EqualFold(r, "HEAD") {
		if br := discoverDefaultBranch(ctx, remoteURL, auth); br != "" {
			return plumbing.ReferenceName(br), nil
		}
		return "", fmt.Errorf("could not discover default branch")
	}
	if strings.HasPrefix(r, "refs/") {
		return plumbing.ReferenceName(r), nil
	}
	if looksLikeTag(r) {
		return plumbing.ReferenceName("refs/tags/" + r), nil
	}
	return plumbing.ReferenceName("refs/heads/" + r), nil
}

func looksLikeTag(r string) bool {
	if strings.HasPrefix(strings.ToLower(r), "v") {
		return true
	}
	for _, c := range r {
		if (c < '0' || c > '9') && c != '.' && c != '-' && c != '_' && c != 'v' {
			return false
		}
	}
	return true
}

func discoverDefaultBranch(ctx context.Context, remoteURL string, auth transport.AuthMethod) string {
	r := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{Name: "origin", URLs: []string{remoteURL}})
	refs, err := r.ListContext(ctx, &git.ListOptions{Auth: auth})
	if err != nil || len(refs) == 0 {
		return "refs/heads/main"
	}
	var hasMain, hasMaster bool
	for _, ref := range refs {
		if ref.Name() == plumbing.HEAD && ref.Target().IsBranch() {
			return ref.Target().String()
		}
		if ref.Name() == plumbing.ReferenceName("refs/heads/main") {
			hasMain = true
		}
		if ref.Name() == plumbing.ReferenceName("refs/heads/master") {
			hasMaster = true
		}
	}
	if hasMain {
		return "refs/heads/main"
	}
	if hasMaster {
		return "refs/heads/master"
	}
	return "refs/heads/main"
}
