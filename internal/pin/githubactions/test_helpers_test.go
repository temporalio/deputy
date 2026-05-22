package githubactions

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-github/v63/github"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/picatz/deputy/internal/pin"
)

// testGHClient creates a GitHub client pointing at a test server URL.
func testGHClient(t *testing.T, baseURL string) *github.Client {
	t.Helper()
	client, err := github.NewEnterpriseClient(baseURL+"/", baseURL+"/upload/", nil)
	if err != nil {
		t.Fatalf("creating test GitHub client: %v", err)
	}
	return client
}

// mapFSAdapter wraps fstest.MapFS to implement scalibrfs.FS.
type mapFSAdapter struct {
	fstest.MapFS
}

func (m *mapFSAdapter) Open(name string) (fs.File, error) {
	return m.MapFS.Open(name)
}

var _ scalibrfs.FS = (*mapFSAdapter)(nil)

// testMapFS creates a scalibrfs.FS from file entries for discovery tests.
func testMapFS(files map[string]string) scalibrfs.FS {
	m := fstest.MapFS{}
	for path, content := range files {
		m[path] = &fstest.MapFile{Data: []byte(strings.TrimSpace(content) + "\n")}
	}
	return &mapFSAdapter{m}
}

// refNames extracts dependency names from a slice of refs.
func refNames(refs []pin.Ref) []string {
	names := make([]string, len(refs))
	for i, r := range refs {
		names[i] = r.Name
	}
	return names
}

// writerTestRoot creates a temp directory with a file, opens an os.Root,
// and returns the root. Writer tests need real files because they test
// actual file writes and permission preservation.
func writerTestRoot(t *testing.T, relPath, content string) *os.Root {
	t.Helper()
	tmp := t.TempDir()
	full := filepath.Join(tmp, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(tmp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}
