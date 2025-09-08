package analysis

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	pb "deps.dev/api/v3"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/licensecheck"
)

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
	raw, err := client.GetVersion(ctx, &pb.GetVersionRequest{VersionKey: &pb.VersionKey{System: pb.System_GO, Name: name, Version: v}})
	if err != nil || raw == nil || len(raw.Licenses) == 0 {
		return []string{"?"}
	}
	return raw.Licenses
}

// LocalRepoLicenseScan scans a local repository directory (root + limited depth)
// for license-looking files and returns detected SPDX identifiers (best effort).
// Depth limit keeps performance bounded. Hidden directories (like .git) skipped.
func LocalRepoLicenseScan(root string) []string {
	if root == "" {
		return nil
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil
	}
	var candidates []string
	// First pass: root-level typical filenames
	baseNames := []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt", "COPYRIGHT", "UNLICENSE"}
	for _, n := range baseNames {
		p := filepath.Join(root, n)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			candidates = append(candidates, p)
		}
	}
	// Second pass: walk depth<=2 collecting additional license-like files
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".") && d.Name() != "." { // skip hidden dirs
				return filepath.SkipDir
			}
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}
		if strings.Count(rel, string(os.PathSeparator)) > 2 {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if strings.HasPrefix(name, "license") || strings.HasPrefix(name, "copying") || name == "copyright" || name == "unlicense" || strings.HasPrefix(name, "licence") {
			candidates = append(candidates, p)
		}
		return nil
	})
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
			data, err := os.ReadFile(f)
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

// (deprecated) defaultGOPATH helper removed with module cache scanning approach.

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
	repoURL := fmt.Sprintf("https://github.com/%s/%s.git", parts[1], parts[2])
	// Shallow clone into temp dir
	dir, err := os.MkdirTemp("", "deputy-lic-remote-*")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(dir)
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
		opts.Auth = &http.BasicAuth{Username: "oauth2", Password: tok}
	}
	if _, err := git.PlainCloneContext(ctx, dir, false, opts); err != nil {
		return nil
	}
	return scanLocalLicenseFiles(dir)
}

// scanLocalLicenseFiles returns detected license IDs for standard candidate filenames.
func scanLocalLicenseFiles(root string) []string {
	candidates := []string{"LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt", "COPYRIGHT"}
	seen := map[string]struct{}{}
	var out []string
	for _, c := range candidates {
		p := filepath.Join(root, c)
		data, err := os.ReadFile(p)
		if err != nil || len(data) == 0 {
			continue
		}
		ids := DetectLicenseIDs(data)
		for _, id := range ids {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

// ExtractLicensesFromReader allows tests to exercise detection on arbitrary content.
func ExtractLicensesFromReader(r io.Reader) []string {
	b, _ := io.ReadAll(r)
	return DetectLicenseIDs(b)
}
