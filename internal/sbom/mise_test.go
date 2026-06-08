package sbomx

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"

	"github.com/temporalio/deputy/internal/mise"
)

func TestAddMiseLockReferences_MultiPlatform(t *testing.T) {
	n := &sbom.Node{Name: "node", Version: "20.11.0"}
	md := &mise.Metadata{
		LockedVersion: "20.11.0",
		Platforms: map[string]mise.LockedPlatform{
			"linux-x64":   {Checksum: "sha256:aaaa", Size: 100, URL: "https://example/linux"},
			"macos-arm64": {Checksum: "sha256:bbbb", URL: "https://example/mac"},
		},
	}
	addMiseLockReferences(n, md)

	if len(n.ExternalReferences) != 2 {
		t.Fatalf("got %d external refs, want 2", len(n.ExternalReferences))
	}
	// Deterministic order: linux-x64 sorts before macos-arm64.
	if n.ExternalReferences[0].Url != "https://example/linux" {
		t.Errorf("first ref url = %q", n.ExternalReferences[0].Url)
	}
	if got := n.ExternalReferences[0].Hashes[int32(sbom.HashAlgorithm_SHA256)]; got != "aaaa" {
		t.Errorf("linux checksum = %q, want aaaa", got)
	}
	if n.ExternalReferences[0].Type != sbom.ExternalReference_DOWNLOAD {
		t.Errorf("ref type = %v", n.ExternalReferences[0].Type)
	}
	// Multi-platform: no ambiguous component-level hash.
	if len(n.Hashes) != 0 {
		t.Errorf("multi-platform should not set component hash, got %v", n.Hashes)
	}
}

func TestAddMiseLockReferences_SinglePlatformSetsComponentHash(t *testing.T) {
	n := &sbom.Node{Name: "ripgrep", Version: "14.1.1"}
	md := &mise.Metadata{
		LockedVersion: "14.1.1",
		Platforms: map[string]mise.LockedPlatform{
			"linux-x64": {Checksum: "sha256:cccc"},
		},
	}
	addMiseLockReferences(n, md)

	if got := n.Hashes[int32(sbom.HashAlgorithm_SHA256)]; got != "cccc" {
		t.Errorf("component hash = %q, want cccc", got)
	}
}

func TestAddMiseLockReferences_LockedVersionProperty(t *testing.T) {
	// Declared version fuzzy "20"; lock pins exact 20.11.0 -> property recorded.
	n := &sbom.Node{Name: "node", Version: "20"}
	md := &mise.Metadata{LockedVersion: "20.11.0"}
	addMiseLockReferences(n, md)

	found := false
	for _, p := range n.Properties {
		if p.Name == "deputy:lockedVersion" && p.Data == "20.11.0" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected deputy:lockedVersion property, got %+v", n.Properties)
	}
}

func TestAddMiseLockReferences_RequestedVersionProperty(t *testing.T) {
	n := &sbom.Node{Name: "node", Version: "20.11.0"}
	md := &mise.Metadata{Version: "20", LockedVersion: "20.11.0"}
	addMiseLockReferences(n, md)

	foundRequested := false
	foundLocked := false
	for _, p := range n.Properties {
		switch {
		case p.Name == "deputy:requestedVersion" && p.Data == "20":
			foundRequested = true
		case p.Name == "deputy:lockedVersion":
			foundLocked = true
		}
	}
	if !foundRequested {
		t.Errorf("expected deputy:requestedVersion property, got %+v", n.Properties)
	}
	if foundLocked {
		t.Errorf("did not expect deputy:lockedVersion when node version is exact, got %+v", n.Properties)
	}
}
