package asdfx

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/google/osv-scalibr/extractor/filesystem"

	"github.com/temporalio/deputy/internal/purlx"
)

type mockFileAPI struct{ path string }

func (m *mockFileAPI) Path() string { return m.path }
func (m *mockFileAPI) Stat() (fs.FileInfo, error) {
	return &mockFileInfo{name: m.path}, nil
}

type mockFileInfo struct{ name string }

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return 0 }
func (m *mockFileInfo) Mode() fs.FileMode  { return 0o644 }
func (m *mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m *mockFileInfo) IsDir() bool        { return false }
func (m *mockFileInfo) Sys() any           { return nil }

func TestFileRequired(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{".tool-versions", true},
		{"sub/.tool-versions", true},
		{"mise.toml", false},
		{"go.mod", false},
	}
	ext := New()
	for _, tt := range tests {
		if got := ext.FileRequired(&mockFileAPI{path: tt.path}); got != tt.want {
			t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestExtract(t *testing.T) {
	content := "nodejs 22.5.0\npython 3.11 3.12\nruby system\ngolang ref:abc\n"
	ext := New()
	inv, err := ext.Extract(context.Background(), &filesystem.ScanInput{
		Path:   ".tool-versions",
		Reader: strings.NewReader(content),
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	// nodejs(1) + python(2); ruby=system and golang=ref skipped.
	if len(inv.Packages) != 3 {
		t.Fatalf("got %d packages, want 3: %+v", len(inv.Packages), inv.Packages)
	}
	for _, p := range inv.Packages {
		if p.PURLType != purlx.TypeAsdf {
			t.Errorf("package %q PURLType = %q, want %q", p.Name, p.PURLType, purlx.TypeAsdf)
		}
		if p.Name == "ruby" || p.Name == "golang" {
			t.Errorf("unexpected skipped tool present: %q", p.Name)
		}
	}
}
