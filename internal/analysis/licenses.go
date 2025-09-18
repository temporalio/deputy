package analysis

import (
	"context"
	"fmt"
	"io"
	nethttp "net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	pb "deps.dev/api/v3"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/licensecheck"
	"github.com/picatz/deputy/internal/repository"
	"github.com/picatz/deputy/internal/repository/workspace"
	"golang.org/x/sync/singleflight"
)

var defaultLicenseFilenames = []string{
	"LICENSE",
	"LICENSE.txt",
	"LICENSE.md",
	"COPYING",
	"COPYING.txt",
	"COPYRIGHT",
	"UNLICENSE",
}

// DepsClient abstracts deps.dev client method GetVersion.
type DepsClient interface {
	GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.Version, error)
}

// FetchLicensesForPackage queries deps.dev for license info for a module name@version.
// Returns ["?"] on error or missing data to preserve existing UX.
func FetchLicensesForPackage(ctx context.Context, client DepsClient, name, version string) []string {
	if version == "" || name == "" {
		return []string{"?"}
	}
	v := version
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	key := name + "@" + v
	var cached []string
	if readCache("depsdev", key, &cached) && len(cached) > 0 {
		return cached
	}
	raw, err := client.GetVersion(ctx, &pb.GetVersionRequest{VersionKey: &pb.VersionKey{System: pb.System_GO, Name: name, Version: v}})
	if err != nil || raw == nil || len(raw.Licenses) == 0 {
		return []string{"?"}
	}
	writeCache("depsdev", key, raw.Licenses)
	return raw.Licenses
}

// LocalRepoLicenseScan inspects a workspace-backed repository (depth-limited)
// for license-looking files and returns detected SPDX identifiers (best effort).
// Hidden directories (like .git) are skipped and the traversal stays shallow
// to keep performance bounded regardless of backend storage.
func LocalRepoLicenseScan(ws workspace.FS) []string {
	if ws == nil {
		return nil
	}
	const maxSeparatorCount = 2
	var candidates []string
	for _, name := range defaultLicenseFilenames {
		if fi, err := ws.Stat(name); err == nil && !fi.IsDir() {
			candidates = append(candidates, name)
		}
	}
	stack := []string{"."}
	for len(stack) > 0 {
		idx := len(stack) - 1
		current := stack[idx]
		stack = stack[:idx]
		entries, err := ws.ReadDir(current)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			rel := name
			if current != "." {
				rel = filepath.Join(current, name)
			}
			if entry.IsDir() {
				if strings.HasPrefix(name, ".") && name != "." {
					continue
				}
				if strings.Count(rel, string(os.PathSeparator)) > maxSeparatorCount {
					continue
				}
				stack = append(stack, rel)
				continue
			}
			if strings.Count(rel, string(os.PathSeparator)) > maxSeparatorCount {
				continue
			}
			lower := strings.ToLower(name)
			if strings.HasPrefix(lower, "license") || strings.HasPrefix(lower, "copying") || lower == "copyright" || lower == "unlicense" || strings.HasPrefix(lower, "licence") {
				candidates = append(candidates, rel)
			}
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	type res struct{ id string }
	ch := make(chan res, len(candidates))
	var wg sync.WaitGroup
	for _, f := range candidates {
		f := f
		wg.Add(1)
		go func() {
			defer wg.Done()
			data, err := ws.ReadFile(f)
			if err != nil {
				return
			}
			for _, id := range DetectLicenseIDs(data) {
				if id != "" {
					ch <- res{id: id}
				}
			}
		}()
	}
	wg.Wait()
	close(ch)
	seen := map[string]struct{}{}
	var out []string
	for r := range ch {
		if _, ok := seen[r.id]; ok {
			continue
		}
		seen[r.id] = struct{}{}
		out = append(out, r.id)
	}
	sort.Strings(out)
	return out
}

var (
	remoteLicenseMemo    sync.Map // string -> []string
	remoteLicenseGroup   singleflight.Group
	githubHTTPClientOnce sync.Once
	githubHTTPClient     *nethttp.Client
)

// MergeLicenseSources merges deps.dev licenses (primary) with locally scanned
// ones (secondary). Returns '?' if both empty. Removes duplicates.
func MergeLicenseSources(primary, local []string) []string {
	set := map[string]struct{}{}
	for _, s := range primary {
		if s != "" && s != "?" {
			set[s] = struct{}{}
		}
	}
	for _, s := range local {
		if s != "" && s != "?" {
			set[s] = struct{}{}
		}
	}
	if len(set) == 0 {
		return []string{"?"}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// DetectLicenseIDs scans raw license text bytes and returns unique SPDX style IDs.
func DetectLicenseIDs(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	cov := licensecheck.Scan(b)
	if len(cov.Match) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, m := range cov.Match {
		id := m.ID
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Remote module license scanning (best effort). Currently supports github.com
// modules by constructing the repository URL and tagging the version if it
// looks like a tag. If cloning fails, returns nil silently.
func RemoteModuleLicenseScan(ctx context.Context, modulePath, version string) []string {
	if modulePath == "" {
		return nil
	}
	if !strings.HasPrefix(modulePath, "github.com/") {
		return nil
	}
	parts := strings.Split(modulePath, "/")
	if len(parts) < 3 {
		return nil
	}
	key := modulePath + "@" + version
	if cached, ok := remoteLicenseMemo.Load(key); ok {
		return cloneStrings(cached.([]string))
	}
	var diskCached []string
	if version != "" && readCache("license-scan", key, &diskCached) && len(diskCached) > 0 {
		remoteLicenseMemo.Store(key, cloneStrings(diskCached))
		return cloneStrings(diskCached)
	}
	result, err, _ := remoteLicenseGroup.Do(key, func() (interface{}, error) {
		if cached, ok := remoteLicenseMemo.Load(key); ok {
			return cloneStrings(cached.([]string)), nil
		}
		if version != "" && len(diskCached) > 0 {
			return cloneStrings(diskCached), nil
		}
		if ids, err := fetchLicensesFromGitHubRaw(ctx, parts[1], parts[2], version); err == nil && len(ids) > 0 {
			if version != "" {
				writeCache("license-scan", key, ids)
			}
			remoteLicenseMemo.Store(key, cloneStrings(ids))
			return ids, nil
		}
		repoURL := fmt.Sprintf("https://github.com/%s/%s.git", parts[1], parts[2])
		opts := &git.CloneOptions{URL: repoURL, Depth: 1, SingleBranch: true, Tags: git.NoTags}
		// Attempt to pick ref from version (tag) if present
		if version != "" {
			v := version
			if !strings.HasPrefix(v, "v") {
				v = "v" + v
			}
			opts.ReferenceName = plumbing.ReferenceName("refs/tags/" + v)
		}
		// Optional GitHub token for rate limits
		if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
			opts.Auth = &githttp.BasicAuth{Username: "oauth2", Password: tok}
		}
		src, err := repository.CloneInMemory(ctx, opts)
		if err != nil {
			return nil, err
		}
		defer src.Close()
		ids := LocalRepoLicenseScan(src.Workspace)
		if version != "" && len(ids) > 0 {
			writeCache("license-scan", key, ids)
		}
		remoteLicenseMemo.Store(key, cloneStrings(ids))
		return ids, nil
	})
	if err != nil {
		return nil
	}
	if ids, ok := result.([]string); ok {
		return cloneStrings(ids)
	}
	return nil
}

// ExtractLicensesFromReader allows tests to exercise detection on arbitrary content.
func ExtractLicensesFromReader(r io.Reader) []string {
	b, _ := io.ReadAll(r)
	return DetectLicenseIDs(b)
}

func cloneStrings(src []string) []string {
	if src == nil {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

func getGitHubHTTPClient() *nethttp.Client {
	githubHTTPClientOnce.Do(func() {
		githubHTTPClient = &nethttp.Client{Timeout: 10 * time.Second}
	})
	return githubHTTPClient
}

func fetchLicensesFromGitHubRaw(ctx context.Context, owner, repo, version string) ([]string, error) {
	ref := deriveGitRef(version)
	if ref == "" {
		return nil, fmt.Errorf("unable to derive git ref")
	}
	client := getGitHubHTTPClient()
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	seen := map[string]struct{}{}
	var out []string
	for _, name := range defaultLicenseFilenames {
		url := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, ref, name)
		req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "deputy-license-scan")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == nethttp.StatusNotFound {
			resp.Body.Close()
			continue
		}
		if resp.StatusCode != nethttp.StatusOK {
			resp.Body.Close()
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || len(data) == 0 {
			continue
		}
		for _, id := range DetectLicenseIDs(data) {
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no license files via raw")
	}
	sort.Strings(out)
	return out, nil
}

func deriveGitRef(version string) string {
	if version == "" {
		return ""
	}
	v := version
	if idx := strings.Index(v, "+"); idx != -1 {
		v = v[:idx]
	}
	if commit := pseudoVersionCommit(v); commit != "" {
		return commit
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

func pseudoVersionCommit(version string) string {
	parts := strings.Split(version, "-")
	if len(parts) < 3 {
		return ""
	}
	commit := parts[len(parts)-1]
	if len(commit) < 7 || len(commit) > 40 {
		return ""
	}
	commit = strings.ToLower(commit)
	for _, r := range commit {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return commit
}
