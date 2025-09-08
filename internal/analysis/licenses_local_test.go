package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func Test_LocalRepoLicenseScan_detectsMIT(t *testing.T) {
	tmp := t.TempDir()
	// create a fake repo root with a LICENSE file
	mit := `MIT License

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
	if err := os.WriteFile(filepath.Join(tmp, "LICENSE"), []byte(mit), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	ids := LocalRepoLicenseScan(tmp)
	if len(ids) == 0 {
		t.Fatalf("expected at least one id")
	}
	foundMIT := false
	for _, id := range ids {
		if strings.Contains(strings.ToUpper(id), "MIT") {
			foundMIT = true
		}
	}
	if !foundMIT {
		t.Fatalf("expected MIT in %v", ids)
	}
}

func Test_MergeLicenseSources(t *testing.T) {
	merged := MergeLicenseSources([]string{"Apache-2.0"}, []string{"MIT", "Apache-2.0"})
	if len(merged) != 2 {
		t.Fatalf("expected 2 unique licenses, got %v", merged)
	}
}

func Test_LocalRepoLicenseScan_missing_returns_nil(t *testing.T) {
	if got := LocalRepoLicenseScan(filepath.Join(t.TempDir(), "does-not-exist")); got != nil {
		t.Fatalf("expected nil for missing dir, got %v", got)
	}
}
