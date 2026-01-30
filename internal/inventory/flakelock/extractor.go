// Package flakelock provides extraction of Nix flake inputs from flake.lock files.
//
// Nix flakes use flake.lock files to pin their input dependencies (other flakes,
// GitHub repos, tarballs, etc.). This extractor parses these lockfiles to enumerate
// the flake's dependencies for inventory and SBOM generation.
//
// Unlike language package managers, flake.lock entries are typically references to
// Git repositories or tarballs, not versioned packages in a registry. However,
// they can be mapped to vulnerability databases when the input is a known project
// (e.g., nixpkgs versions can be correlated with NixOS security advisories).
//
// The Extractor type implements the SCALIBR filesystem.Extractor interface,
// allowing seamless integration with Deputy's inventory system.
//
// See: https://nixos.wiki/wiki/Flakes
// See: https://nix.dev/manual/nix/stable/command-ref/new-cli/nix3-flake.html#lock-files
package flakelock

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/picatz/deputy/internal/ecosystem"
)

const (
	// Name is the unique name of this extractor.
	Name = "nix/flakelock"
)

// Extractor implements the SCALIBR filesystem.Extractor interface
// for extracting dependencies from Nix flake.lock files.
type Extractor struct{}

// Ensure Extractor implements the filesystem.Extractor interface.
var _ filesystem.Extractor = (*Extractor)(nil)

// New creates a new flakelock extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name returns the unique name of this extractor.
func (e *Extractor) Name() string { return Name }

// Version returns the extractor version.
func (e *Extractor) Version() int { return 1 }

// Requirements returns plugin requirements (none for this extractor).
func (e *Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if this file should be processed by the extractor.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "flake.lock"
}

// Extract parses a flake.lock file and returns the discovered flake inputs as packages.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	lock, err := ParseFlakeLock(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("flakelock: %w", err)
	}

	flakeInputs, err := Extract(ctx, lock, input.Path)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("flakelock: %w", err)
	}

	packages := make([]*extractor.Package, 0, len(flakeInputs))
	for _, fi := range flakeInputs {
		pkg := flakeInputToPackage(fi)
		if pkg != nil {
			packages = append(packages, pkg)
		}
	}

	return inventory.Inventory{Packages: packages}, nil
}

// flakeInputToPackage converts a FlakeInput to a SCALIBR extractor.Package.
func flakeInputToPackage(fi FlakeInput) *extractor.Package {
	name := fi.Name
	if fi.Owner != "" && fi.Repo != "" {
		name = fi.Owner + "/" + fi.Repo
	}

	version := fi.FullVersion()

	pkg := &extractor.Package{
		Name:      name,
		Version:   version,
		PURLType:  purl.TypeNix,
		Locations: []string{fi.Location},
		Metadata: &Metadata{
			InputName:    fi.Name,
			Type:         fi.Type,
			Owner:        fi.Owner,
			Repo:         fi.Repo,
			Rev:          fi.Rev,
			Ref:          fi.Ref,
			NarHash:      fi.NarHash,
			IsFlake:      fi.IsFlake,
			LastModified: fi.LastModified,
			Dir:          fi.Dir,
		},
	}

	return pkg
}

// Metadata holds parsing information for a Nix flake input.
// This aligns with OSV-SCALIBR's metadata pattern.
type Metadata struct {
	InputName    string
	Type         string
	Owner        string
	Repo         string
	Rev          string
	Ref          string
	NarHash      string
	IsFlake      bool
	LastModified int64
	Dir          string
}

// FlakeLock represents the structure of a flake.lock file.
// The lock file is a JSON document containing a graph of flake inputs.
type FlakeLock struct {
	// Version is the lock file format version (currently 7 is common).
	Version int `json:"version"`

	// Root identifies the root node of the flake graph.
	Root string `json:"root"`

	// Nodes maps node identifiers to their definitions.
	Nodes map[string]Node `json:"nodes"`
}

// Node represents a single node in the flake input graph.
type Node struct {
	// Inputs maps input names to node identifiers (edges in the graph).
	Inputs map[string]any `json:"inputs"`

	// Locked contains the resolved/locked reference information.
	Locked *LockedRef `json:"locked,omitempty"`

	// Original contains the original (unlocked) reference from flake.nix.
	Original *OriginalRef `json:"original,omitempty"`

	// Flake indicates whether this is a flake input (default true).
	// Non-flake inputs are raw source trees without a flake.nix.
	Flake *bool `json:"flake,omitempty"`
}

// IsFlake returns true if this node represents a flake (has flake.nix).
// Defaults to true if the field is not set.
func (n Node) IsFlake() bool {
	if n.Flake == nil {
		return true
	}
	return *n.Flake
}

// LockedRef contains the locked (pinned) reference for a flake input.
type LockedRef struct {
	// Type is the flake reference type (github, git, path, tarball, etc.).
	Type string `json:"type"`

	// Owner is the repository owner (for github/gitlab types).
	Owner string `json:"owner,omitempty"`

	// Repo is the repository name (for github/gitlab types).
	Repo string `json:"repo,omitempty"`

	// Rev is the Git commit hash.
	Rev string `json:"rev,omitempty"`

	// Ref is the Git branch or tag name.
	Ref string `json:"ref,omitempty"`

	// URL is the direct URL (for tarball/file types).
	URL string `json:"url,omitempty"`

	// Path is the local path (for path type).
	Path string `json:"path,omitempty"`

	// NarHash is the hash of the Nix Archive serialization (integrity check).
	NarHash string `json:"narHash,omitempty"`

	// LastModified is the timestamp of the last modification.
	LastModified int64 `json:"lastModified,omitempty"`

	// RevCount is the number of commits (for Git repos).
	RevCount int `json:"revCount,omitempty"`

	// Dir is the subdirectory containing the flake (for monorepos).
	Dir string `json:"dir,omitempty"`

	// Host is a custom host (for self-hosted GitHub/GitLab).
	Host string `json:"host,omitempty"`
}

// OriginalRef contains the original (unlocked) reference from flake.nix.
type OriginalRef struct {
	Type  string `json:"type"`
	Owner string `json:"owner,omitempty"`
	Repo  string `json:"repo,omitempty"`
	Ref   string `json:"ref,omitempty"`
	ID    string `json:"id,omitempty"` // For indirect references (registry lookups)
	URL   string `json:"url,omitempty"`
	Path  string `json:"path,omitempty"`
	Dir   string `json:"dir,omitempty"`
}

// FlakeInput represents an extracted flake input dependency.
type FlakeInput struct {
	// Name is the input name as declared in flake.nix.
	Name string

	// Type is the flake reference type (github, gitlab, git, tarball, path, indirect).
	Type string

	// Owner is the repository owner (for GitHub/GitLab).
	Owner string

	// Repo is the repository name.
	Repo string

	// Rev is the pinned Git commit hash.
	Rev string

	// Ref is the Git branch/tag reference.
	Ref string

	// URL is the resolved URL for the input.
	URL string

	// NarHash is the Nix Archive hash for integrity.
	NarHash string

	// IsFlake indicates if this input is a proper flake.
	IsFlake bool

	// LastModified is when the input was last modified.
	LastModified int64

	// Dir is the subdirectory for monorepo flakes.
	Dir string

	// Location is the path to the flake.lock file.
	Location string
}

// PURL returns a Package URL for this flake input.
// Since there's no official PURL type for Nix, we use pkg:nix/ with qualifiers.
func (f FlakeInput) PURL() string {
	switch f.Type {
	case "github":
		// For GitHub inputs, we could use pkg:github/ but stick with nix for consistency
		name := f.Owner + "/" + f.Repo
		if f.Rev != "" {
			return fmt.Sprintf("pkg:nix/%s@%s", name, f.Rev)
		}
		return fmt.Sprintf("pkg:nix/%s", name)
	case "gitlab":
		name := f.Owner + "/" + f.Repo
		if f.Rev != "" {
			return fmt.Sprintf("pkg:nix/%s@%s?type=gitlab", name, f.Rev)
		}
		return fmt.Sprintf("pkg:nix/%s?type=gitlab", name)
	case "indirect":
		// Registry references like "nixpkgs"
		if f.Rev != "" {
			return fmt.Sprintf("pkg:nix/%s@%s", f.Name, f.Rev)
		}
		return fmt.Sprintf("pkg:nix/%s", f.Name)
	default:
		if f.Rev != "" {
			return fmt.Sprintf("pkg:nix/%s@%s", f.Name, f.Rev)
		}
		return fmt.Sprintf("pkg:nix/%s", f.Name)
	}
}

// Version returns a version string for this input.
// For flakes, the "version" is typically the Git commit or ref.
func (f FlakeInput) Version() string {
	if f.Rev != "" {
		// Prefer short rev for display
		if len(f.Rev) > 12 {
			return f.Rev[:12]
		}
		return f.Rev
	}
	if f.Ref != "" {
		return f.Ref
	}
	return ""
}

// FullVersion returns the complete version identifier (full commit hash).
func (f FlakeInput) FullVersion() string {
	if f.Rev != "" {
		return f.Rev
	}
	if f.Ref != "" {
		return f.Ref
	}
	return ""
}

// ParseFlakeLock parses a flake.lock file from the given reader.
func ParseFlakeLock(r io.Reader) (*FlakeLock, error) {
	var lock FlakeLock
	if err := json.NewDecoder(r).Decode(&lock); err != nil {
		return nil, fmt.Errorf("parse flake.lock: %w", err)
	}
	return &lock, nil
}

// Extract extracts all flake inputs from a parsed lock file.
func Extract(ctx context.Context, lock *FlakeLock, location string) ([]FlakeInput, error) {
	if lock == nil {
		return nil, nil
	}

	var inputs []FlakeInput

	// The root node contains the direct inputs
	rootNode, ok := lock.Nodes[lock.Root]
	if !ok {
		return nil, fmt.Errorf("root node %q not found in lock file", lock.Root)
	}

	// Walk all non-root nodes to extract inputs
	for nodeID, node := range lock.Nodes {
		// Skip the root node (it represents the flake itself, not a dependency)
		if nodeID == lock.Root {
			continue
		}

		// Skip nodes without locked references
		if node.Locked == nil {
			continue
		}

		// Find the input name by looking at what references this node
		inputName := findInputName(lock, nodeID, rootNode)
		if inputName == "" {
			inputName = nodeID // Fallback to node ID
		}

		input := FlakeInput{
			Name:         inputName,
			Type:         node.Locked.Type,
			Owner:        node.Locked.Owner,
			Repo:         node.Locked.Repo,
			Rev:          node.Locked.Rev,
			Ref:          node.Locked.Ref,
			URL:          node.Locked.URL,
			NarHash:      node.Locked.NarHash,
			IsFlake:      node.IsFlake(),
			LastModified: node.Locked.LastModified,
			Dir:          node.Locked.Dir,
			Location:     location,
		}

		// For indirect references, get the ID from original
		if node.Locked.Type == "indirect" && node.Original != nil {
			if node.Original.ID != "" {
				input.Name = node.Original.ID
			}
		}

		inputs = append(inputs, input)
	}

	return inputs, nil
}

// findInputName finds the name used to reference a node from the root.
func findInputName(lock *FlakeLock, targetNodeID string, rootNode Node) string {
	for inputName, ref := range rootNode.Inputs {
		switch v := ref.(type) {
		case string:
			if v == targetNodeID {
				return inputName
			}
		case []any:
			// Follows reference: ["nixpkgs"] means follow nixpkgs's nixpkgs
			// The node ID is typically the last element
			if len(v) > 0 {
				if last, ok := v[len(v)-1].(string); ok && last == targetNodeID {
					return inputName
				}
			}
		}
	}
	return ""
}

// IsFlakeLockFile returns true if the given path is a flake.lock file.
func IsFlakeLockFile(path string) bool {
	return filepath.Base(path) == "flake.lock"
}

// NixpkgsInfo contains information about a nixpkgs input.
type NixpkgsInfo struct {
	// Owner is the GitHub owner (usually "NixOS").
	Owner string

	// Repo is the repository name (usually "nixpkgs").
	Repo string

	// Rev is the Git commit hash.
	Rev string

	// Ref is the branch/tag (e.g., "nixos-24.05", "nixos-unstable").
	Ref string

	// Channel extracts the NixOS channel name from the ref if possible.
	Channel string
}

// ExtractNixpkgsInfo extracts nixpkgs-specific information from a flake input.
// Returns nil if the input is not a nixpkgs reference.
func ExtractNixpkgsInfo(input FlakeInput) *NixpkgsInfo {
	// Check if this is a nixpkgs input
	isNixpkgs := false

	if input.Type == "github" && input.Owner == "NixOS" && input.Repo == "nixpkgs" {
		isNixpkgs = true
	} else if input.Type == "indirect" && strings.ToLower(input.Name) == "nixpkgs" {
		isNixpkgs = true
	} else if strings.Contains(strings.ToLower(input.Name), "nixpkgs") {
		isNixpkgs = true
	}

	if !isNixpkgs {
		return nil
	}

	info := &NixpkgsInfo{
		Owner: input.Owner,
		Repo:  input.Repo,
		Rev:   input.Rev,
		Ref:   input.Ref,
	}

	// Extract channel from ref
	if info.Ref != "" {
		info.Channel = extractChannel(info.Ref)
	}

	return info
}

// extractChannel extracts the NixOS channel from a ref.
// Examples: "nixos-24.05" -> "24.05", "nixos-unstable" -> "unstable"
func extractChannel(ref string) string {
	ref = strings.ToLower(ref)
	if strings.HasPrefix(ref, "nixos-") {
		return strings.TrimPrefix(ref, "nixos-")
	}
	if strings.HasPrefix(ref, "nixpkgs-") {
		return strings.TrimPrefix(ref, "nixpkgs-")
	}
	return ref
}

// UpstreamEcosystem returns the upstream ecosystem info for vulnerability lookups.
// For nixpkgs inputs, this enables correlation with NixOS security advisories.
func (f FlakeInput) UpstreamEcosystem() *ecosystem.NixUpstreamInfo {
	// For now, flake inputs themselves don't map to upstream ecosystems
	// (they're meta-packages/repositories, not individual packages).
	// Individual packages within nixpkgs would need separate handling.
	return nil
}

// GraphEdge represents an edge in the flake input dependency graph.
type GraphEdge struct {
	From string // Parent input name (or "root" for direct inputs)
	To   string // Child input name
}

// ExtractGraph extracts the dependency graph from a flake.lock file.
// It returns edges representing the input dependency relationships.
func ExtractGraph(lock *FlakeLock) ([]GraphEdge, error) {
	if lock == nil {
		return nil, nil
	}

	var edges []GraphEdge

	// Walk all nodes and their inputs
	for nodeID, node := range lock.Nodes {
		for inputName, ref := range node.Inputs {
			var targetNodeID string
			switch v := ref.(type) {
			case string:
				targetNodeID = v
			case []any:
				// Follows reference: take the last element
				if len(v) > 0 {
					if last, ok := v[len(v)-1].(string); ok {
						targetNodeID = last
					}
				}
			}
			if targetNodeID == "" {
				continue
			}

			// Skip self-references
			if targetNodeID == nodeID {
				continue
			}

			// For root node, use "root" as the source
			from := nodeID
			if nodeID == lock.Root {
				from = "root"
			}

			edges = append(edges, GraphEdge{
				From: from,
				To:   targetNodeID,
			})

			// Also track the input name mapping
			_ = inputName // Input name is available for additional context
		}
	}

	return edges, nil
}

// DirectInputs returns the names of direct inputs (from the root node).
func DirectInputs(lock *FlakeLock) []string {
	if lock == nil {
		return nil
	}

	rootNode, ok := lock.Nodes[lock.Root]
	if !ok {
		return nil
	}

	var direct []string
	for inputName := range rootNode.Inputs {
		direct = append(direct, inputName)
	}
	return direct
}

// IsDirectInput returns true if the given node is a direct input of the root.
func IsDirectInput(lock *FlakeLock, nodeID string) bool {
	if lock == nil {
		return false
	}

	rootNode, ok := lock.Nodes[lock.Root]
	if !ok {
		return false
	}

	for _, ref := range rootNode.Inputs {
		switch v := ref.(type) {
		case string:
			if v == nodeID {
				return true
			}
		case []any:
			if len(v) > 0 {
				if last, ok := v[len(v)-1].(string); ok && last == nodeID {
					return true
				}
			}
		}
	}
	return false
}

// UpdateInput represents an update to a flake input.
type UpdateInput struct {
	Name       string // Input name to update
	NewRev     string // New Git revision
	NewRef     string // New branch/tag reference (optional)
	NewNarHash string // New NAR hash (required for integrity)
}

// ApplyUpdate applies an update to a flake.lock, returning the modified JSON.
// This enables programmatic updates without shelling out to `nix flake update`.
//
// Note: This is a best-effort function. For production use, prefer running
// `nix flake lock --update-input <name>` which properly recalculates hashes.
func ApplyUpdate(lock *FlakeLock, update UpdateInput) (*FlakeLock, error) {
	if lock == nil {
		return nil, fmt.Errorf("lock file is nil")
	}
	if update.Name == "" {
		return nil, fmt.Errorf("input name is required")
	}
	if update.NewRev == "" && update.NewRef == "" {
		return nil, fmt.Errorf("at least one of NewRev or NewRef is required")
	}

	// Find the node for this input
	rootNode, ok := lock.Nodes[lock.Root]
	if !ok {
		return nil, fmt.Errorf("root node not found")
	}

	// Find the node ID for the input
	var targetNodeID string
	for inputName, ref := range rootNode.Inputs {
		if inputName == update.Name {
			switch v := ref.(type) {
			case string:
				targetNodeID = v
			case []any:
				if len(v) > 0 {
					if last, ok := v[len(v)-1].(string); ok {
						targetNodeID = last
					}
				}
			}
			break
		}
	}

	if targetNodeID == "" {
		return nil, fmt.Errorf("input %q not found", update.Name)
	}

	node, ok := lock.Nodes[targetNodeID]
	if !ok {
		return nil, fmt.Errorf("node %q not found", targetNodeID)
	}

	if node.Locked == nil {
		return nil, fmt.Errorf("node %q has no locked reference", targetNodeID)
	}

	// Create updated node
	newLocked := *node.Locked
	if update.NewRev != "" {
		newLocked.Rev = update.NewRev
	}
	if update.NewRef != "" {
		newLocked.Ref = update.NewRef
	}
	if update.NewNarHash != "" {
		newLocked.NarHash = update.NewNarHash
	}

	// Create a copy of the lock with the updated node
	newLock := &FlakeLock{
		Version: lock.Version,
		Root:    lock.Root,
		Nodes:   make(map[string]Node, len(lock.Nodes)),
	}
	for k, v := range lock.Nodes {
		if k == targetNodeID {
			newLock.Nodes[k] = Node{
				Inputs:   v.Inputs,
				Locked:   &newLocked,
				Original: v.Original,
				Flake:    v.Flake,
			}
		} else {
			newLock.Nodes[k] = v
		}
	}

	return newLock, nil
}

// SerializeFlakeLock serializes a FlakeLock to JSON with proper formatting.
func SerializeFlakeLock(lock *FlakeLock) ([]byte, error) {
	return json.MarshalIndent(lock, "", "  ")
}
