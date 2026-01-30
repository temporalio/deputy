package nixstore

import (
	"context"
	"io/fs"
	"testing"
	"time"

	"github.com/google/osv-scalibr/extractor/filesystem"
)

func TestParseNixStorePath(t *testing.T) {
	// Note: Nix store hashes use base32 with alphabet: 0-9, a-d, f-n, p-s, v-z
	// (no e, o, t, u characters)
	validHash := "0123456789abcdfghmnpqrsvwxyz0123" // 32 chars using valid chars

	tests := []struct {
		name        string
		path        string
		wantName    string
		wantVersion string
		wantHash    string
		wantOutput  string
	}{
		{
			name:        "simple package",
			path:        "/nix/store/" + validHash + "-openssl-3.0.12",
			wantName:    "openssl",
			wantVersion: "3.0.12",
			wantHash:    validHash,
		},
		{
			name:        "package with output",
			path:        "/nix/store/" + validHash + "-openssl-3.0.12-dev",
			wantName:    "openssl",
			wantVersion: "3.0.12",
			wantHash:    validHash,
			wantOutput:  "dev",
		},
		{
			name:        "python package",
			path:        "/nix/store/" + validHash + "-python3.11-requests-2.31.0",
			wantName:    "python3.11-requests",
			wantVersion: "2.31.0",
			wantHash:    validHash,
		},
		{
			name:        "perl package",
			path:        "/nix/store/" + validHash + "-perl5.38.2-FCGI-ProcManager-0.28",
			wantName:    "perl5.38.2-FCGI-ProcManager",
			wantVersion: "0.28",
			wantHash:    validHash,
		},
		{
			name:        "nested path",
			path:        "/nix/store/" + validHash + "-curl-8.4.0/bin/curl",
			wantName:    "curl",
			wantVersion: "8.4.0",
			wantHash:    validHash,
		},
		{
			name:        "relative path",
			path:        "nix/store/" + validHash + "-nginx-1.25.3",
			wantName:    "nginx",
			wantVersion: "1.25.3",
			wantHash:    validHash,
		},
		{
			name:     "not a nix path",
			path:     "/usr/lib/openssl",
			wantName: "",
		},
		{
			name:     "invalid hash",
			path:     "/nix/store/invalid-openssl-1.0",
			wantName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, version, hash, output := parseNixStorePath(tt.path)

			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
			if hash != tt.wantHash {
				t.Errorf("hash = %q, want %q", hash, tt.wantHash)
			}
			if output != tt.wantOutput {
				t.Errorf("output = %q, want %q", output, tt.wantOutput)
			}
		})
	}
}

func TestParseCPEName(t *testing.T) {
	tests := []struct {
		name        string
		cpeName     string
		wantVendor  string
		wantProduct string
		wantVersion string
	}{
		{
			name:        "CPE 2.2 format",
			cpeName:     "cpe:/o:nixos:nixos:24.11",
			wantVendor:  "nixos",
			wantProduct: "nixos",
			wantVersion: "24.11",
		},
		{
			name:        "CPE 2.3 format",
			cpeName:     "cpe:2.3:o:nixos:nixos:24.11:*:*:*:*:*:*:*",
			wantVendor:  "nixos",
			wantProduct: "nixos",
			wantVersion: "24.11",
		},
		{
			name:        "CPE 2.3 application",
			cpeName:     "cpe:2.3:a:openssl:openssl:3.0.12:*:*:*:*:*:*:*",
			wantVendor:  "openssl",
			wantProduct: "openssl",
			wantVersion: "3.0.12",
		},
		{
			name:    "empty",
			cpeName: "",
		},
		{
			name:    "invalid format",
			cpeName: "not-a-cpe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vendor, product, version := ParseCPEName(tt.cpeName)

			if vendor != tt.wantVendor {
				t.Errorf("vendor = %q, want %q", vendor, tt.wantVendor)
			}
			if product != tt.wantProduct {
				t.Errorf("product = %q, want %q", product, tt.wantProduct)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

func TestNixStorePath(t *testing.T) {
	validHash := "0123456789abcdfghmnpqrsvwxyz0123"

	t.Run("parse and PURL", func(t *testing.T) {
		var p NixStorePath
		ok := p.Parse("/nix/store/" + validHash + "-openssl-3.0.12")
		if !ok {
			t.Fatal("Parse returned false")
		}

		if p.Name != "openssl" {
			t.Errorf("Name = %q, want %q", p.Name, "openssl")
		}
		if p.Version != "3.0.12" {
			t.Errorf("Version = %q, want %q", p.Version, "3.0.12")
		}

		purl := p.PURL()
		if purl != "pkg:nix/openssl@3.0.12" {
			t.Errorf("PURL = %q, want %q", purl, "pkg:nix/openssl@3.0.12")
		}
	})

	t.Run("invalid path", func(t *testing.T) {
		var p NixStorePath
		ok := p.Parse("/usr/lib/openssl")
		if ok {
			t.Error("Parse returned true for invalid path")
		}
	})
}

func TestExtractor(t *testing.T) {
	e := New()

	t.Run("name and version", func(t *testing.T) {
		if e.Name() != Name {
			t.Errorf("Name = %q, want %q", e.Name(), Name)
		}
		if e.Version() != 1 {
			t.Errorf("Version = %d, want 1", e.Version())
		}
	})

	t.Run("requirements", func(t *testing.T) {
		req := e.Requirements()
		if req == nil {
			t.Error("Requirements returned nil")
		}
	})

	t.Run("file required", func(t *testing.T) {
		tests := []struct {
			path string
			want bool
		}{
			{"/nix/store/abc-test-1.0/bin/test", true},
			{"nix/store/abc-test-1.0/lib/test.so", true},
			{"/usr/bin/test", false},
			{"package.json", false},
		}

		for _, tt := range tests {
			api := &testFileAPI{path: tt.path}
			got := e.FileRequired(api)
			if got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		}
	})

	t.Run("extract package", func(t *testing.T) {
		validHash := "0123456789abcdfghmnpqrsvwxyz0123"
		input := &filesystem.ScanInput{
			Path: "/nix/store/" + validHash + "-openssl-3.0.12/lib/libssl.so",
			FS:   &testFS{},
		}

		inv, err := e.Extract(context.Background(), input)
		if err != nil {
			t.Fatalf("Extract error: %v", err)
		}

		if len(inv.Packages) != 1 {
			t.Fatalf("got %d packages, want 1", len(inv.Packages))
		}

		pkg := inv.Packages[0]
		if pkg.Name != "openssl" {
			t.Errorf("Name = %q, want %q", pkg.Name, "openssl")
		}
		if pkg.Version != "3.0.12" {
			t.Errorf("Version = %q, want %q", pkg.Version, "3.0.12")
		}

		meta, ok := pkg.Metadata.(*Metadata)
		if !ok {
			t.Fatal("Metadata is not *Metadata")
		}
		if meta.PackageHash != validHash {
			t.Errorf("PackageHash = %q, want correct hash", meta.PackageHash)
		}
	})
}

// testFileAPI is a mock filesystem.FileAPI for testing.
type testFileAPI struct {
	path    string
	content []byte
}

func (f *testFileAPI) Path() string { return f.path }

func (f *testFileAPI) Stat() (fs.FileInfo, error) {
	return &testFileInfo{name: f.path, size: int64(len(f.content))}, nil
}

func (f *testFileAPI) Open() (fs.File, error) {
	return nil, nil
}

type testFileInfo struct {
	name string
	size int64
}

func (i *testFileInfo) Name() string       { return i.name }
func (i *testFileInfo) Size() int64        { return i.size }
func (i *testFileInfo) Mode() fs.FileMode  { return 0644 }
func (i *testFileInfo) ModTime() time.Time { return time.Time{} }
func (i *testFileInfo) IsDir() bool        { return false }
func (i *testFileInfo) Sys() any           { return nil }

// testFS is a mock filesystem for testing.
type testFS struct{}

func (f *testFS) Open(name string) (fs.File, error) {
	return nil, fs.ErrNotExist
}

func (f *testFS) ReadDir(name string) ([]fs.DirEntry, error) {
	return nil, fs.ErrNotExist
}

func (f *testFS) Stat(name string) (fs.FileInfo, error) {
	return nil, fs.ErrNotExist
}

func (f *testFS) ReadFile(path string) ([]byte, error) {
	// Return mock os-release for NixOS
	if path == "/etc/os-release" || path == "etc/os-release" {
		return []byte(`ID=nixos
VERSION_CODENAME=vicuna
VERSION_ID=24.11
CPE_NAME="cpe:/o:nixos:nixos:24.11"
PRETTY_NAME="NixOS 24.11 (Vicuna)"
`), nil
	}
	return nil, fs.ErrNotExist
}
