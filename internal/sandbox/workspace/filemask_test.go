package workspace

import (
	"os"
	"path/filepath"
	"testing"

	sandboxv1 "github.com/temporalio/deputy/gen/deputy/sandbox/v1"
)

func TestFileMaskerShouldMask(t *testing.T) {
	tests := []struct {
		name     string
		config   *sandboxv1.FileMaskConfig
		path     string
		wantMode sandboxv1.FileMaskMode
	}{
		{
			name:     "no config returns unspecified",
			config:   nil,
			path:     "test.txt",
			wantMode: sandboxv1.FileMaskMode_FILE_MASK_MODE_UNSPECIFIED,
		},
		{
			name: "explicit rule masks file",
			config: &sandboxv1.FileMaskConfig{
				MaskRules: []*sandboxv1.FileMaskRule{
					{
						Pattern: "*.env",
						Mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
					},
				},
			},
			path:     ".env",
			wantMode: sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
		},
		{
			name: "expose pattern overrides mask rule",
			config: &sandboxv1.FileMaskConfig{
				MaskRules: []*sandboxv1.FileMaskRule{
					{
						Pattern: "*.json",
						Mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
					},
				},
				ExposePatterns: []string{"package.json"},
			},
			path:     "package.json",
			wantMode: sandboxv1.FileMaskMode_FILE_MASK_MODE_UNSPECIFIED,
		},
		{
			name: "default mode applies when no rules match",
			config: &sandboxv1.FileMaskConfig{
				DefaultMode: sandboxv1.FileMaskMode_FILE_MASK_MODE_READ_ONLY,
			},
			path:     "anything.txt",
			wantMode: sandboxv1.FileMaskMode_FILE_MASK_MODE_READ_ONLY,
		},
		{
			name: "later rules override earlier rules",
			config: &sandboxv1.FileMaskConfig{
				MaskRules: []*sandboxv1.FileMaskRule{
					{
						Pattern: "*.txt",
						Mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
					},
					{
						Pattern: "important.txt",
						Mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_READ_ONLY,
					},
				},
			},
			path:     "important.txt",
			wantMode: sandboxv1.FileMaskMode_FILE_MASK_MODE_READ_ONLY,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fm := NewFileMasker(tc.config)
			gotMode, _ := fm.ShouldMask(tc.path)
			if gotMode != tc.wantMode {
				t.Errorf("ShouldMask(%q) = %v, want %v", tc.path, gotMode, tc.wantMode)
			}
		})
	}
}

func TestFileMaskerPresets(t *testing.T) {
	tests := []struct {
		name     string
		preset   sandboxv1.FileMaskPreset
		path     string
		wantMode sandboxv1.FileMaskMode
	}{
		{
			name:     "secrets preset hides .env",
			preset:   sandboxv1.FileMaskPreset_FILE_MASK_PRESET_SECRETS,
			path:     ".env",
			wantMode: sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
		},
		{
			name:     "secrets preset hides .pem files",
			preset:   sandboxv1.FileMaskPreset_FILE_MASK_PRESET_SECRETS,
			path:     "server.pem",
			wantMode: sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
		},
		{
			name:     "secrets preset hides credentials.json",
			preset:   sandboxv1.FileMaskPreset_FILE_MASK_PRESET_SECRETS,
			path:     "credentials.json",
			wantMode: sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
		},
		{
			name:     "IDE preset hides .vscode",
			preset:   sandboxv1.FileMaskPreset_FILE_MASK_PRESET_IDE,
			path:     ".vscode/settings.json",
			wantMode: sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
		},
		{
			name:     "build artifacts preset hides dist",
			preset:   sandboxv1.FileMaskPreset_FILE_MASK_PRESET_BUILD_ARTIFACTS,
			path:     "dist/bundle.js",
			wantMode: sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
		},
		{
			name:     "build artifacts preset hides __pycache__",
			preset:   sandboxv1.FileMaskPreset_FILE_MASK_PRESET_BUILD_ARTIFACTS,
			path:     "__pycache__/module.pyc",
			wantMode: sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := &sandboxv1.FileMaskConfig{
				Presets: []sandboxv1.FileMaskPreset{tc.preset},
			}
			fm := NewFileMasker(config)
			gotMode, _ := fm.ShouldMask(tc.path)
			if gotMode != tc.wantMode {
				t.Errorf("ShouldMask(%q) with preset %v = %v, want %v",
					tc.path, tc.preset, gotMode, tc.wantMode)
			}
		})
	}
}

func TestFileMaskerSupplyChainPreset(t *testing.T) {
	config := &sandboxv1.FileMaskConfig{
		Presets: []sandboxv1.FileMaskPreset{
			sandboxv1.FileMaskPreset_FILE_MASK_PRESET_SUPPLY_CHAIN,
		},
	}
	fm := NewFileMasker(config)

	// These should be hidden
	hiddenFiles := []string{
		".env",
		".git/objects/pack",
		"node_modules/lodash/index.js",
		"vendor/github.com/pkg/package.go",
	}

	for _, path := range hiddenFiles {
		mode, _ := fm.ShouldMask(path)
		if mode != sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN {
			t.Errorf("Supply chain preset should hide %q, got mode %v", path, mode)
		}
	}

	// These should be exposed (lockfiles)
	exposedFiles := []string{
		"package-lock.json",
		"go.sum",
		"go.mod",
		"Cargo.lock",
		"yarn.lock",
	}

	for _, path := range exposedFiles {
		mode, _ := fm.ShouldMask(path)
		if mode == sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN {
			t.Errorf("Supply chain preset should expose %q, but it's hidden", path)
		}
	}
}

func TestCreateMaskedWorkspace(t *testing.T) {
	// Create source directory with various files
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// Create test files
	files := map[string]string{
		"visible.txt":        "visible content",
		".env":               "SECRET=value",
		"subdir/normal.txt":  "normal file",
		"subdir/.secret.key": "private key",
	}

	for path, content := range files {
		fullPath := filepath.Join(srcDir, path)
		os.MkdirAll(filepath.Dir(fullPath), 0755)
		os.WriteFile(fullPath, []byte(content), 0644)
	}

	// Create masker with secrets preset
	config := &sandboxv1.FileMaskConfig{
		Presets: []sandboxv1.FileMaskPreset{
			sandboxv1.FileMaskPreset_FILE_MASK_PRESET_SECRETS,
		},
	}
	fm := NewFileMasker(config)

	// Create masked workspace
	if err := fm.CreateMaskedWorkspace(srcDir, dstDir); err != nil {
		t.Fatalf("CreateMaskedWorkspace() error = %v", err)
	}

	// visible.txt should exist with content
	content, err := os.ReadFile(filepath.Join(dstDir, "visible.txt"))
	if err != nil {
		t.Errorf("visible.txt should exist: %v", err)
	} else if string(content) != "visible content" {
		t.Errorf("visible.txt has wrong content: %q", content)
	}

	// .env should NOT exist (hidden)
	if _, err := os.Stat(filepath.Join(dstDir, ".env")); !os.IsNotExist(err) {
		t.Error(".env should be hidden (not exist)")
	}

	// subdir/normal.txt should exist
	if _, err := os.Stat(filepath.Join(dstDir, "subdir", "normal.txt")); err != nil {
		t.Errorf("subdir/normal.txt should exist: %v", err)
	}

	// subdir/.secret.key should NOT exist (hidden by secrets preset)
	if _, err := os.Stat(filepath.Join(dstDir, "subdir", ".secret.key")); !os.IsNotExist(err) {
		t.Error("subdir/.secret.key should be hidden")
	}
}

func TestCreateMaskedWorkspaceEmptyMode(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// Create source file
	os.WriteFile(filepath.Join(srcDir, "config.txt"), []byte("secret config"), 0644)

	// Create masker with empty mode
	config := &sandboxv1.FileMaskConfig{
		MaskRules: []*sandboxv1.FileMaskRule{
			{
				Pattern: "*.txt",
				Mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_EMPTY,
			},
		},
	}
	fm := NewFileMasker(config)

	if err := fm.CreateMaskedWorkspace(srcDir, dstDir); err != nil {
		t.Fatalf("CreateMaskedWorkspace() error = %v", err)
	}

	// File should exist but be empty
	content, err := os.ReadFile(filepath.Join(dstDir, "config.txt"))
	if err != nil {
		t.Fatalf("config.txt should exist: %v", err)
	}
	if len(content) != 0 {
		t.Errorf("config.txt should be empty, got %d bytes", len(content))
	}
}

func TestCreateMaskedWorkspacePlaceholderMode(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	os.WriteFile(filepath.Join(srcDir, "secret.txt"), []byte("secret"), 0644)

	config := &sandboxv1.FileMaskConfig{
		MaskRules: []*sandboxv1.FileMaskRule{
			{
				Pattern: "*.txt",
				Mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_PLACEHOLDER,
				Reason:  "security policy",
			},
		},
	}
	fm := NewFileMasker(config)

	if err := fm.CreateMaskedWorkspace(srcDir, dstDir); err != nil {
		t.Fatalf("CreateMaskedWorkspace() error = %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dstDir, "secret.txt"))
	if err != nil {
		t.Fatalf("secret.txt should exist: %v", err)
	}

	// Should contain placeholder text
	if string(content) == "secret" {
		t.Error("secret.txt should have placeholder, not original content")
	}
	if len(content) == 0 {
		t.Error("secret.txt should have placeholder content")
	}
}

func TestGenerateHiddenPaths(t *testing.T) {
	// Create workspace with files
	workspaceDir := t.TempDir()

	files := []string{
		"normal.txt",
		".env",
		"subdir/.secret",
		"subdir/public.txt",
	}

	for _, f := range files {
		path := filepath.Join(workspaceDir, f)
		os.MkdirAll(filepath.Dir(path), 0755)
		os.WriteFile(path, []byte("content"), 0644)
	}

	config := &sandboxv1.FileMaskConfig{
		MaskRules: []*sandboxv1.FileMaskRule{
			{
				Pattern: ".env",
				Mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
			},
			{
				Pattern: ".*secret*",
				Mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
			},
		},
	}
	fm := NewFileMasker(config)

	paths := fm.GenerateHiddenPaths(workspaceDir)

	// Should include .env and .secret paths
	pathSet := make(map[string]bool)
	for _, p := range paths {
		pathSet[p] = true
	}

	if !pathSet["/workspace/.env"] {
		t.Error("Should include /workspace/.env")
	}
	if !pathSet["/workspace/subdir/.secret"] {
		t.Error("Should include /workspace/subdir/.secret")
	}
	if pathSet["/workspace/normal.txt"] {
		t.Error("Should NOT include /workspace/normal.txt")
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		path    string
		pattern string
		want    bool
	}{
		// Simple patterns
		{".env", ".env", true},
		{".env", ".env*", true},
		{".env.local", ".env*", true},
		{"test.txt", "*.txt", true},
		{"test.go", "*.txt", false},

		// Path patterns
		{"dir/.env", ".env", true},
		{"dir/subdir/.env", ".env", true},

		// ** patterns
		{".git/objects/pack", "**/.git/**", true},
		{".git/config", "**/.git/**", true},
		{"node_modules/pkg/index.js", "**/node_modules/**", true},
		{"src/node_modules/pkg.js", "**/node_modules/**", true},

		// Specific file in any directory
		{"package.json", "**/package.json", true},
		{"node_modules/pkg/package.json", "**/package.json", true},
	}

	for _, tc := range tests {
		t.Run(tc.path+"_"+tc.pattern, func(t *testing.T) {
			got := matchPattern(tc.path, tc.pattern)
			if got != tc.want {
				t.Errorf("matchPattern(%q, %q) = %v, want %v",
					tc.path, tc.pattern, got, tc.want)
			}
		})
	}
}

func TestDefaultSupplyChainMask(t *testing.T) {
	mask := DefaultSupplyChainMask()

	if len(mask.Presets) != 1 {
		t.Errorf("Expected 1 preset, got %d", len(mask.Presets))
	}
	if mask.Presets[0] != sandboxv1.FileMaskPreset_FILE_MASK_PRESET_SUPPLY_CHAIN {
		t.Errorf("Expected SUPPLY_CHAIN preset, got %v", mask.Presets[0])
	}
}

func TestDefaultAgentMask(t *testing.T) {
	mask := DefaultAgentMask()

	if mask.DefaultMode != sandboxv1.FileMaskMode_FILE_MASK_MODE_READ_ONLY {
		t.Errorf("Expected READ_ONLY default mode, got %v", mask.DefaultMode)
	}

	if len(mask.Presets) != 2 {
		t.Errorf("Expected 2 presets, got %d", len(mask.Presets))
	}

	// Should have expose patterns for source code
	if len(mask.ExposePatterns) == 0 {
		t.Error("Expected expose patterns for source code")
	}

	// Check that common source files are exposed
	fm := NewFileMasker(mask)
	sourceFiles := []string{"main.go", "index.js", "app.py"}
	for _, f := range sourceFiles {
		mode, _ := fm.ShouldMask(f)
		if mode == sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN {
			t.Errorf("Source file %q should be exposed", f)
		}
	}
}
