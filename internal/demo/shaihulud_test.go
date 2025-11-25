package demo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/go-github/v63/github"
	"github.com/google/osv-scalibr/extractor"
)

func TestParseVersionList(t *testing.T) {
	versions := parseVersionList("= 0.0.7 || =0.0.8 || v1.0.0")
	got := strings.Join(versions, ",")
	want := "0.0.7,0.0.8,1.0.0"
	if got != want {
		t.Fatalf("unexpected versions: got %q want %q", got, want)
	}
}

func TestMatchPackages(t *testing.T) {
	set := iocSet{}
	set.add("@scope/pkg", "0.1.0")
	pkgs := []*extractor.Package{{Name: "@scope/pkg", Version: "0.1.0"}, {Name: "@scope/pkg", Version: "0.2.0"}}
	matches := matchPackages(pkgs, set)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Package != "@scope/pkg" || matches[0].Version != "0.1.0" {
		t.Fatalf("unexpected match: %+v", matches[0])
	}
}

func TestScanShaiHuludFindsIOC(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	ctx := t.Context()

	tmp := t.TempDir()
	iocRepo := makeNPMRepo(t, filepath.Join(tmp, "ioc"), map[string]string{"@actbase/react-absolute": "0.8.3"})
	cleanRepo := makeNPMRepo(t, filepath.Join(tmp, "clean"), map[string]string{"react": "19.0.0"})

	ghServer := newGitHubStub(t, "acme", []stubRepo{{Name: "ioc", CloneURL: iocRepo}, {Name: "clean", CloneURL: cleanRepo}})
	defer ghServer.Close()

	ghClient := github.NewClient(ghServer.Client())
	base, _ := neturl.Parse(ghServer.URL + "/")
	ghClient.BaseURL = base

	iocServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("Package,Version\n@actbase/react-absolute,= 0.8.3\n"))
	}))
	defer iocServer.Close()

	results, err := ScanShaiHulud(ctx, Options{
		Owner:        "acme",
		GitHubClient: ghClient,
		HTTPClient:   iocServer.Client(),
		IOCURL:       iocServer.URL,
		Concurrency:  2,
	})
	if err != nil {
		t.Fatalf("ScanShaiHulud: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 repo results, got %d", len(results))
	}

	matched := false
	for _, res := range results {
		if res.Name == "ioc" {
			if len(res.Matches) != 1 {
				t.Fatalf("expected 1 match in ioc repo, got %d (err=%v)", len(res.Matches), res.Error)
			}
			if res.Matches[0].Package != "@actbase/react-absolute" {
				t.Fatalf("unexpected package match: %+v", res.Matches[0])
			}
			matched = true
		}
		if res.Name == "clean" && res.Error != nil {
			t.Fatalf("clean repo error: %v", res.Error)
		}
	}
	if !matched {
		t.Fatalf("ioc repo match not found in results")
	}
}

type stubRepo struct {
	Name     string `json:"name"`
	CloneURL string `json:"clone_url"`
}

func newGitHubStub(t *testing.T, owner string, repos []stubRepo) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/orgs/"+owner+"/repos", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(repos)
	})
	return httptest.NewServer(mux)
}

func makeNPMRepo(t *testing.T, dir string, deps map[string]string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	pkgJSON := map[string]any{
		"name":         filepath.Base(dir),
		"version":      "1.0.0",
		"dependencies": deps,
	}
	pkgBytes, _ := json.Marshal(pkgJSON)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), pkgBytes, 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	lock := map[string]any{
		"name":            filepath.Base(dir),
		"version":         "1.0.0",
		"lockfileVersion": 3,
	}
	packages := map[string]any{"": map[string]any{"dependencies": deps}}
	for name, version := range deps {
		packages[filepath.ToSlash(filepath.Join("node_modules", name))] = map[string]any{"version": version}
	}
	lock["packages"] = packages

	lockBytes, _ := json.Marshal(lock)
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), lockBytes, 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init repo: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if _, err := wt.Add("."); err != nil {
		t.Fatalf("add files: %v", err)
	}
	_, err = wt.Commit("init", &git.CommitOptions{Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	return dir
}
