package license

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/picatz/deputy/internal/repository/workspace"
)

func Test_LocalRepoLicenseScan_detectsMIT(t *testing.T) {
	licenseText := `MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`

	t.Run("disk workspace", func(t *testing.T) {
		tmp := t.TempDir()
		if err := os.WriteFile(filepath.Join(tmp, "LICENSE"), []byte(licenseText), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		ws, err := workspace.NewDir(tmp)
		if err != nil {
			t.Fatalf("workspace: %v", err)
		}
		t.Cleanup(func() { _ = ws.Close() })
		ids := LocalRepoLicenseScan(ws)
		assertContainsMIT(t, ids)
	})

	t.Run("memory workspace", func(t *testing.T) {
		ws := workspace.NewMemory()
		t.Cleanup(func() { _ = ws.Close() })
		if err := ws.WriteFile("LICENSE", []byte(licenseText), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		ids := LocalRepoLicenseScan(ws)
		assertContainsMIT(t, ids)
	})
}

func assertContainsMIT(t *testing.T, ids []string) {
	t.Helper()
	if len(ids) == 0 {
		t.Fatalf("expected at least one id")
	}
	for _, id := range ids {
		if strings.Contains(strings.ToUpper(id), "MIT") {
			return
		}
	}
	t.Fatalf("expected MIT in %v", ids)
}

func Test_MergeLicenseSources(t *testing.T) {
	merged := MergeLicenseSources([]string{"Apache-2.0"}, []string{"MIT", "Apache-2.0"})
	if len(merged) != 2 {
		t.Fatalf("expected 2 unique licenses, got %v", merged)
	}
}

func Test_LocalRepoLicenseScan_missing_returns_nil(t *testing.T) {
	ws := workspace.NewMemory()
	t.Cleanup(func() { _ = ws.Close() })
	if got := LocalRepoLicenseScan(ws); got != nil {
		t.Fatalf("expected nil for empty workspace, got %v", got)
	}
}

func Test_LocalRepoLicenseScan_nilWorkspace_returnsNil(t *testing.T) {
	if got := LocalRepoLicenseScan(nil); got != nil {
		t.Fatalf("expected nil for nil workspace, got %v", got)
	}
}
