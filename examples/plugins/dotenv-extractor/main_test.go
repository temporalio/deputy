package main

import (
	"context"
	"os"
	"os/exec"
	"testing"

	invplugin "github.com/temporalio/deputy/internal/inventory/plugin"
)

func TestDotenvExtractor(t *testing.T) {
	// Build the plugin
	tmpFile, err := os.CreateTemp("", "deputy-extractor-dotenv-*")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	tmpFile.Close()
	pluginPath := tmpFile.Name()
	defer os.Remove(pluginPath)

	cmd := exec.Command("go", "build", "-o", pluginPath, ".")
	cmd.Dir = "."
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build plugin: %v\n%s", err, output)
	}

	// Create client
	ctx := context.Background()
	client, err := invplugin.NewClient(ctx, pluginPath)
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	// Test Info
	info := client.ExtractorInfo()
	if info == nil {
		t.Fatal("info is nil")
	}
	if info.Name != "config/dotenv" {
		t.Errorf("name = %q, want %q", info.Name, "config/dotenv")
	}
	if info.Ecosystem != "config" {
		t.Errorf("ecosystem = %q, want %q", info.Ecosystem, "config")
	}

	// Test FileRequired
	tests := []struct {
		path     string
		expected bool
	}{
		{".env", true},
		{".env.local", true},
		{".env.production", true},
		{"production.env", true},
		{"config.yaml", false},
		{"README.md", false},
	}

	for _, tt := range tests {
		required, err := client.FileRequired(ctx, tt.path, false, 0644, 100)
		if err != nil {
			t.Errorf("FileRequired(%q): %v", tt.path, err)
			continue
		}
		if required != tt.expected {
			t.Errorf("FileRequired(%q) = %v, want %v", tt.path, required, tt.expected)
		}
	}

	// Test Extract
	envContents := []byte(`# Database config
DATABASE_URL=postgres://localhost/myapp
API_KEY=sk-12345
DEBUG=true
`)

	packages, err := client.ExtractPackages(ctx, ".env", envContents, "/project")
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if len(packages) != 1 {
		t.Fatalf("got %d packages, want 1", len(packages))
	}

	pkg := packages[0]
	if pkg.Name != ".env" {
		t.Errorf("package name = %q, want %q", pkg.Name, ".env")
	}
	if pkg.Ecosystem != "config" {
		t.Errorf("package ecosystem = %q, want %q", pkg.Ecosystem, "config")
	}
}
