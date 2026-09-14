package sbomx

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	protoconv "github.com/temporalio/deputy/internal/proto"
)

// directDepFixture is one ecosystem's manifest pair: the file that declares a
// direct dependency and the lockfile that makes the dependency inventoriable,
// plus the package name inventory reports for it.
type directDepFixture struct {
	name    string
	files   map[string]string
	pkgName string
}

// writeSBOMFixture materializes a fixture's files in a fresh directory and
// returns its path.
func writeSBOMFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// commitSBOMFixture makes a fixture directory a Git repository with everything
// committed and returns the commit hash. Passing that hash as the ref is what
// drives the commit-tree collection path; "HEAD" resolves to the working tree
// instead.
func commitSBOMFixture(t *testing.T, dir string) string {
	t.Helper()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if _, err := wt.Add("."); err != nil {
		t.Fatalf("Add: %v", err)
	}
	hash, err := wt.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return hash.String()
}

// sbomDirectDepFixtures are the non-Go ecosystems whose direct dependencies an
// SBOM must classify. Go is covered by the collectors' own tests; these are the
// ecosystems whose manifests the Go-only collector never read.
var sbomDirectDepFixtures = []directDepFixture{
	{
		name: "npm",
		files: map[string]string{
			"package.json": `{"name":"demo","version":"1.0.0","dependencies":{"lodash":"^4.17.21"}}`,
			"package-lock.json": `{
  "name": "demo",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "demo", "version": "1.0.0", "dependencies": {"lodash": "^4.17.21"}},
    "node_modules/lodash": {"version": "4.17.21"}
  }
}`,
		},
		pkgName: "lodash",
	},
	{
		name: "cargo",
		files: map[string]string{
			"Cargo.toml": "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0\"\n",
			"Cargo.lock": "[[package]]\nname = \"serde\"\nversion = \"1.0.197\"\n",
		},
		pkgName: "serde",
	},
	{
		name: "pypi",
		files: map[string]string{
			"requirements.txt": "flask==3.0.0\n",
		},
		pkgName: "flask",
	},
}

// TestSBOMMarksNonGoDirectDependencies pins that an SBOM classifies direct
// dependencies for every ecosystem it inventories, not just Go. The SBOM path
// collected only Go direct modules, so "deputy sbom --policy" handed every npm,
// Cargo, and PyPI component direct=false and a policy scoped to direct
// dependencies silently skipped all of them.
func TestSBOMMarksNonGoDirectDependencies(t *testing.T) {
	for _, fixture := range sbomDirectDepFixtures {
		for _, tc := range []struct {
			name   string
			atRef  bool
			cmtRef string
		}{
			{name: "worktree", atRef: false},
			{name: "commit", atRef: true},
		} {
			t.Run(fixture.name+"/"+tc.name, func(t *testing.T) {
				dir := writeSBOMFixture(t, fixture.files)
				ref := "HEAD"
				if tc.atRef {
					ref = commitSBOMFixture(t, dir)
				}
				result, err := Generate(t.Context(), dir, Options{Ref: ref})
				if err != nil {
					t.Fatalf("Generate: %v", err)
				}
				// Asserted through the classification the SBOM itself performs
				// rather than by looking a name up in the set. The set's keys
				// are an internal layout: an npm entry is keyed by name and
				// version once a lockfile resolves it, so a test that reads a
				// bare name is testing the layout instead of the answer.
				var found bool
				for _, pkg := range result.Packages {
					if pkg.Name != fixture.pkgName {
						continue
					}
					found = true
					if !protoconv.ExtractorPackageIsDirect(pkg, result.Direct) {
						t.Errorf("direct dependency %s@%s not classified direct; Direct = %v",
							pkg.Name, pkg.Version, result.Direct)
					}
				}
				if !found {
					t.Fatalf("inventory did not report %q at all", fixture.pkgName)
				}
			})
		}
	}
}
