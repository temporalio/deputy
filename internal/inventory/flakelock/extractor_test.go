package flakelock

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
)

const sampleFlakeLock = `{
  "nodes": {
    "flake-utils": {
      "inputs": {
        "systems": "systems"
      },
      "locked": {
        "lastModified": 1710146030,
        "narHash": "sha256-SZ5L6eA7HJ/nmkzGG7/ISclqe6oZdOZTNoesiInkXPQ=",
        "owner": "numtide",
        "repo": "flake-utils",
        "rev": "b1d9ab70662946ef0850d488da1c9019f3a9752a",
        "type": "github"
      },
      "original": {
        "owner": "numtide",
        "repo": "flake-utils",
        "type": "github"
      }
    },
    "nixpkgs": {
      "locked": {
        "lastModified": 1716358906,
        "narHash": "sha256-z4jtS6GKF4z8qXzK+S7Lhz3kw1ZTnsoOE0J2L7TQqTg=",
        "owner": "NixOS",
        "repo": "nixpkgs",
        "rev": "57d6973abba7ea108bac64ae7629e7431e0199b6",
        "type": "github"
      },
      "original": {
        "owner": "NixOS",
        "ref": "nixos-24.05",
        "repo": "nixpkgs",
        "type": "github"
      }
    },
    "root": {
      "inputs": {
        "flake-utils": "flake-utils",
        "nixpkgs": "nixpkgs"
      }
    },
    "systems": {
      "locked": {
        "lastModified": 1681028828,
        "narHash": "sha256-Vy1rq5AaRuLzOxct8nz4T6wlgyUR7zLU309k9mBC768=",
        "owner": "nix-systems",
        "repo": "default",
        "rev": "da67096a3b9bf56a91d16901293e51ba5b49a27e",
        "type": "github"
      },
      "original": {
        "owner": "nix-systems",
        "repo": "default",
        "type": "github"
      }
    }
  },
  "root": "root",
  "version": 7
}`

func TestParseFlakeLock(t *testing.T) {
	lock, err := ParseFlakeLock(strings.NewReader(sampleFlakeLock))
	if err != nil {
		t.Fatalf("ParseFlakeLock failed: %v", err)
	}

	if lock.Version != 7 {
		t.Errorf("expected version 7, got %d", lock.Version)
	}

	if lock.Root != "root" {
		t.Errorf("expected root 'root', got %q", lock.Root)
	}

	if len(lock.Nodes) != 4 {
		t.Errorf("expected 4 nodes, got %d", len(lock.Nodes))
	}

	nixpkgs, ok := lock.Nodes["nixpkgs"]
	if !ok {
		t.Fatal("nixpkgs node not found")
	}
	if nixpkgs.Locked == nil {
		t.Fatal("nixpkgs.Locked is nil")
	}
	if nixpkgs.Locked.Owner != "NixOS" {
		t.Errorf("expected owner 'NixOS', got %q", nixpkgs.Locked.Owner)
	}
	if nixpkgs.Locked.Repo != "nixpkgs" {
		t.Errorf("expected repo 'nixpkgs', got %q", nixpkgs.Locked.Repo)
	}
	if nixpkgs.Locked.Type != "github" {
		t.Errorf("expected type 'github', got %q", nixpkgs.Locked.Type)
	}
}

func TestExtract(t *testing.T) {
	lock, err := ParseFlakeLock(strings.NewReader(sampleFlakeLock))
	if err != nil {
		t.Fatalf("ParseFlakeLock failed: %v", err)
	}

	inputs, err := Extract(context.Background(), lock, "test/flake.lock")
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(inputs) != 3 {
		t.Errorf("expected 3 inputs, got %d", len(inputs))
		for _, input := range inputs {
			t.Logf("  - %s (%s)", input.Name, input.Type)
		}
	}

	var foundNixpkgs bool
	for _, input := range inputs {
		if input.Owner == "NixOS" && input.Repo == "nixpkgs" {
			foundNixpkgs = true
			if input.Type != "github" {
				t.Errorf("expected nixpkgs type 'github', got %q", input.Type)
			}
			if input.Rev != "57d6973abba7ea108bac64ae7629e7431e0199b6" {
				t.Errorf("unexpected nixpkgs rev: %q", input.Rev)
			}
			if input.Location != "test/flake.lock" {
				t.Errorf("expected location 'test/flake.lock', got %q", input.Location)
			}
		}
	}
	if !foundNixpkgs {
		t.Error("nixpkgs input not found")
	}
}

func TestFlakeInputPURL(t *testing.T) {
	tests := []struct {
		name     string
		input    FlakeInput
		expected string
	}{
		{
			name: "github with rev",
			input: FlakeInput{
				Type:  "github",
				Owner: "NixOS",
				Repo:  "nixpkgs",
				Rev:   "abc123",
			},
			expected: "pkg:nix/NixOS/nixpkgs@abc123",
		},
		{
			name: "github without rev",
			input: FlakeInput{
				Type:  "github",
				Owner: "numtide",
				Repo:  "flake-utils",
			},
			expected: "pkg:nix/numtide/flake-utils",
		},
		{
			name: "gitlab",
			input: FlakeInput{
				Type:  "gitlab",
				Owner: "group",
				Repo:  "project",
				Rev:   "def456",
			},
			expected: "pkg:nix/group/project@def456?type=gitlab",
		},
		{
			name: "indirect",
			input: FlakeInput{
				Type: "indirect",
				Name: "nixpkgs",
				Rev:  "xyz789",
			},
			expected: "pkg:nix/nixpkgs@xyz789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.PURL()
			if got != tt.expected {
				t.Errorf("PURL() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestFlakeInputVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    FlakeInput
		expected string
	}{
		{
			name:     "short rev",
			input:    FlakeInput{Rev: "abc123"},
			expected: "abc123",
		},
		{
			name:     "long rev truncated",
			input:    FlakeInput{Rev: "57d6973abba7ea108bac64ae7629e7431e0199b6"},
			expected: "57d6973abba7",
		},
		{
			name:     "ref only",
			input:    FlakeInput{Ref: "nixos-24.05"},
			expected: "nixos-24.05",
		},
		{
			name:     "rev preferred over ref",
			input:    FlakeInput{Rev: "abc123", Ref: "main"},
			expected: "abc123",
		},
		{
			name:     "empty",
			input:    FlakeInput{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.Version()
			if got != tt.expected {
				t.Errorf("Version() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestExtractNixpkgsInfo(t *testing.T) {
	tests := []struct {
		name    string
		input   FlakeInput
		wantNil bool
		channel string
	}{
		{
			name: "github nixpkgs",
			input: FlakeInput{
				Type:  "github",
				Owner: "NixOS",
				Repo:  "nixpkgs",
				Ref:   "nixos-24.05",
			},
			wantNil: false,
			channel: "24.05",
		},
		{
			name: "indirect nixpkgs",
			input: FlakeInput{
				Type: "indirect",
				Name: "nixpkgs",
				Ref:  "nixos-unstable",
			},
			wantNil: false,
			channel: "unstable",
		},
		{
			name: "not nixpkgs",
			input: FlakeInput{
				Type:  "github",
				Owner: "numtide",
				Repo:  "flake-utils",
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ExtractNixpkgsInfo(tt.input)
			if tt.wantNil {
				if info != nil {
					t.Errorf("expected nil, got %+v", info)
				}
				return
			}
			if info == nil {
				t.Fatal("expected non-nil, got nil")
			}
			if info.Channel != tt.channel {
				t.Errorf("Channel = %q, want %q", info.Channel, tt.channel)
			}
		})
	}
}

func TestIsFlakeLockFile(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		{"flake.lock", true},
		{"/path/to/project/flake.lock", true},
		{"flake.nix", false},
		{"package-lock.json", false},
		{"flake.lock.bak", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := IsFlakeLockFile(tt.path)
			if got != tt.expected {
				t.Errorf("IsFlakeLockFile(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestNodeIsFlake(t *testing.T) {
	tests := []struct {
		name     string
		node     Node
		expected bool
	}{
		{
			name:     "nil flake field (default true)",
			node:     Node{},
			expected: true,
		},
		{
			name:     "explicit true",
			node:     Node{Flake: boolPtr(true)},
			expected: true,
		},
		{
			name:     "explicit false",
			node:     Node{Flake: boolPtr(false)},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.node.IsFlake()
			if got != tt.expected {
				t.Errorf("IsFlake() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func TestExtractorName(t *testing.T) {
	e := New()
	if e.Name() != Name {
		t.Errorf("Name() = %q, want %q", e.Name(), Name)
	}
}

func TestExtractorFileRequired(t *testing.T) {
	e := &Extractor{}
	tests := []struct {
		path     string
		expected bool
	}{
		{"flake.lock", true},
		{"/home/user/project/flake.lock", true},
		{"flake.nix", false},
		{"package-lock.json", false},
		{"some/path/flake.lock", true},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			api := &testFileAPI{path: tt.path}
			got := e.FileRequired(api)
			if got != tt.expected {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

// testFileAPI implements filesystem.FileAPI for testing
type testFileAPI struct {
	path string
}

func (f *testFileAPI) Path() string                 { return f.path }
func (f *testFileAPI) Stat() (os.FileInfo, error)   { return nil, nil }
func (f *testFileAPI) Open() (io.ReadCloser, error) { return nil, nil }

func TestExtractGraph(t *testing.T) {
	lock, err := ParseFlakeLock(strings.NewReader(sampleFlakeLock))
	if err != nil {
		t.Fatalf("ParseFlakeLock failed: %v", err)
	}

	edges, err := ExtractGraph(lock)
	if err != nil {
		t.Fatalf("ExtractGraph failed: %v", err)
	}

	// We should have edges from:
	// - root -> nixpkgs, flake-utils
	// - flake-utils -> systems
	if len(edges) < 3 {
		t.Errorf("expected at least 3 edges, got %d", len(edges))
	}

	// Check that root has edges to direct inputs
	var hasRootToNixpkgs, hasRootToFlakeUtils bool
	for _, e := range edges {
		if e.From == "root" && e.To == "nixpkgs" {
			hasRootToNixpkgs = true
		}
		if e.From == "root" && e.To == "flake-utils" {
			hasRootToFlakeUtils = true
		}
	}

	if !hasRootToNixpkgs {
		t.Error("expected edge from root to nixpkgs")
	}
	if !hasRootToFlakeUtils {
		t.Error("expected edge from root to flake-utils")
	}
}

func TestDirectInputs(t *testing.T) {
	lock, err := ParseFlakeLock(strings.NewReader(sampleFlakeLock))
	if err != nil {
		t.Fatalf("ParseFlakeLock failed: %v", err)
	}

	direct := DirectInputs(lock)
	if len(direct) != 2 {
		t.Errorf("expected 2 direct inputs, got %d: %v", len(direct), direct)
	}

	hasNixpkgs := false
	hasFlakeUtils := false
	for _, name := range direct {
		if name == "nixpkgs" {
			hasNixpkgs = true
		}
		if name == "flake-utils" {
			hasFlakeUtils = true
		}
	}

	if !hasNixpkgs {
		t.Error("expected nixpkgs in direct inputs")
	}
	if !hasFlakeUtils {
		t.Error("expected flake-utils in direct inputs")
	}
}

func TestIsDirectInput(t *testing.T) {
	lock, err := ParseFlakeLock(strings.NewReader(sampleFlakeLock))
	if err != nil {
		t.Fatalf("ParseFlakeLock failed: %v", err)
	}

	tests := []struct {
		nodeID   string
		expected bool
	}{
		{"nixpkgs", true},
		{"flake-utils", true},
		{"systems", false}, // transitive via flake-utils
		{"nonexistent", false},
	}

	for _, tt := range tests {
		t.Run(tt.nodeID, func(t *testing.T) {
			got := IsDirectInput(lock, tt.nodeID)
			if got != tt.expected {
				t.Errorf("IsDirectInput(%q) = %v, want %v", tt.nodeID, got, tt.expected)
			}
		})
	}
}

func TestApplyUpdate(t *testing.T) {
	lock, err := ParseFlakeLock(strings.NewReader(sampleFlakeLock))
	if err != nil {
		t.Fatalf("ParseFlakeLock failed: %v", err)
	}

	update := UpdateInput{
		Name:       "nixpkgs",
		NewRev:     "abc123def456abc123def456abc123def456abc1",
		NewNarHash: "sha256-newHash=",
	}

	newLock, err := ApplyUpdate(lock, update)
	if err != nil {
		t.Fatalf("ApplyUpdate failed: %v", err)
	}

	// Verify the update was applied
	nixpkgs, ok := newLock.Nodes["nixpkgs"]
	if !ok {
		t.Fatal("nixpkgs node not found in updated lock")
	}

	if nixpkgs.Locked.Rev != update.NewRev {
		t.Errorf("expected rev %q, got %q", update.NewRev, nixpkgs.Locked.Rev)
	}

	if nixpkgs.Locked.NarHash != update.NewNarHash {
		t.Errorf("expected narHash %q, got %q", update.NewNarHash, nixpkgs.Locked.NarHash)
	}

	// Verify other nodes weren't modified
	flakeUtils, ok := newLock.Nodes["flake-utils"]
	if !ok {
		t.Fatal("flake-utils node not found")
	}
	if flakeUtils.Locked.Rev != "b1d9ab70662946ef0850d488da1c9019f3a9752a" {
		t.Error("flake-utils was unexpectedly modified")
	}
}

func TestApplyUpdateErrors(t *testing.T) {
	lock, err := ParseFlakeLock(strings.NewReader(sampleFlakeLock))
	if err != nil {
		t.Fatalf("ParseFlakeLock failed: %v", err)
	}

	tests := []struct {
		name   string
		update UpdateInput
	}{
		{
			name:   "empty name",
			update: UpdateInput{NewRev: "abc123"},
		},
		{
			name:   "no rev or ref",
			update: UpdateInput{Name: "nixpkgs"},
		},
		{
			name:   "nonexistent input",
			update: UpdateInput{Name: "nonexistent", NewRev: "abc123"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ApplyUpdate(lock, tt.update)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestSerializeFlakeLock(t *testing.T) {
	lock, err := ParseFlakeLock(strings.NewReader(sampleFlakeLock))
	if err != nil {
		t.Fatalf("ParseFlakeLock failed: %v", err)
	}

	data, err := SerializeFlakeLock(lock)
	if err != nil {
		t.Fatalf("SerializeFlakeLock failed: %v", err)
	}

	// Parse the serialized output to verify it's valid
	reParsed, err := ParseFlakeLock(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("failed to re-parse serialized lock: %v", err)
	}

	if reParsed.Version != lock.Version {
		t.Errorf("version mismatch: got %d, want %d", reParsed.Version, lock.Version)
	}

	if len(reParsed.Nodes) != len(lock.Nodes) {
		t.Errorf("node count mismatch: got %d, want %d", len(reParsed.Nodes), len(lock.Nodes))
	}
}
