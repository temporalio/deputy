package pin

import (
	"os"
	"path/filepath"
	"testing"
)

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
