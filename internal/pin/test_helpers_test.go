package pin

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-github/v63/github"
	scalibrfs "github.com/google/osv-scalibr/fs"
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

// Compile-time interface check.
var _ scalibrfs.FS = (*mapFSAdapter)(nil)

// testMapFS creates a scalibrfs.FS from file entries for discovery tests.
// Content is trimmed and a trailing newline is added to match real files.
func testMapFS(files map[string]string) scalibrfs.FS {
	m := fstest.MapFS{}
	for path, content := range files {
		m[path] = &fstest.MapFile{Data: []byte(strings.TrimSpace(content) + "\n")}
	}
	return &mapFSAdapter{m}
}

// testMapFSExact creates a scalibrfs.FS preserving exact content (no trimming).
// Use this when whitespace precision matters (e.g., rewrite tests).
func testMapFSExact(files map[string]string) scalibrfs.FS {
	m := fstest.MapFS{}
	for path, content := range files {
		m[path] = &fstest.MapFile{Data: []byte(content)}
	}
	return &mapFSAdapter{m}
}

// refNames extracts dependency names from a slice of refs.
func refNames(refs []Ref) []string {
	names := make([]string, len(refs))
	for i, r := range refs {
		names[i] = r.Name
	}
	return names
}

// refSummary returns a human-readable summary of refs for test failure messages.
func refSummary(refs []Ref) string {
	var parts []string
	for _, r := range refs {
		parts = append(parts, r.Name+":"+r.Version)
	}
	return strings.Join(parts, ", ")
}
