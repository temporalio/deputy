package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCleanPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  error
	}{
		{in: "", want: ".", err: nil},
		{in: ".", want: ".", err: nil},
		{in: "./go.mod", want: "go.mod", err: nil},
		{in: "sub/dir/file", want: "sub/dir/file", err: nil},
		{in: "sub/../file", want: "file", err: nil},
		{in: "../escape", want: "", err: ErrOutsideWorkspace},
		{in: "/abs", want: "", err: ErrOutsideWorkspace},
	}
	for _, tc := range cases {
		got, err := cleanPath(tc.in)
		if !errors.Is(err, tc.err) {
			t.Fatalf("cleanPath(%q) error = %v want %v", tc.in, err, tc.err)
		}
		if got != tc.want {
			t.Fatalf("cleanPath(%q) = %q want %q", tc.in, got, tc.want)
		}
	}
}

func TestDirWorkspace_ReadWrite(t *testing.T) {
	ws, err := NewTempDir("workspace-test")
	if err != nil {
		t.Fatalf("NewTempDir: %v", err)
	}
	root := ws.RootPath()
	if root == "" {
		t.Fatalf("RootPath empty")
	}
	defer ws.Close()

	data := []byte("module example.com/test\n")
	if err := ws.WriteFile("go.mod", data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := ws.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("ReadFile mismatch got %q want %q", got, data)
	}
	entries, err := ws.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "go.mod" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	if err := ws.RemoveAll("."); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("RemoveAll root should error: %v", err)
	}
	if err := ws.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected temp dir removed, stat err=%v", err)
	}
}

func TestMemoryWorkspace_ReadWrite(t *testing.T) {
	ws := NewMemory()
	defer ws.Close()

	if !ws.IsVirtual() {
		t.Fatalf("expected virtual workspace")
	}

	if err := ws.MkdirAll("sub", 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	content := []byte("hello")
	if err := ws.WriteFile("sub/file.txt", content, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := ws.ReadFile("sub/file.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("ReadFile mismatch got %q want %q", got, content)
	}
	if _, err := ws.ReadFile("../evil"); !errors.Is(err, ErrOutsideWorkspace) {
		t.Fatalf("expected ErrOutsideWorkspace, got %v", err)
	}
}

func TestDirWorkspace_ScanRoots(t *testing.T) {
	dir := t.TempDir()
	ws, err := NewDir(dir)
	if err != nil {
		t.Fatalf("NewDir: %v", err)
	}
	defer ws.Close()
	roots := ws.ScanRoots()
	if len(roots) != 1 {
		t.Fatalf("unexpected roots len: %d", len(roots))
	}
	if roots[0].Path != filepath.Clean(dir) {
		t.Fatalf("root path mismatch: %q vs %q", roots[0].Path, dir)
	}
	if roots[0].IsVirtual() {
		t.Fatalf("dir workspace should not be virtual")
	}
}

func TestMemoryWorkspace_ScanRootsVirtual(t *testing.T) {
	ws := NewMemory()
	defer ws.Close()
	roots := ws.ScanRoots()
	if len(roots) != 1 {
		t.Fatalf("unexpected roots len: %d", len(roots))
	}
	if !roots[0].IsVirtual() {
		t.Fatalf("expected virtual root")
	}
	if roots[0].Path != "" {
		t.Fatalf("expected empty path")
	}
}
