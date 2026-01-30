// Package nixstore provides extraction of Nix packages from the Nix store.
//
// This extractor scans /nix/store paths to identify installed packages,
// complementing the flakelock extractor for runtime package discovery.
// It follows OSV-SCALIBR's approach for parsing Nix store directory names.
//
// Nix store paths follow the pattern:
//
//	/nix/store/<hash>-<name>-<version>[-<output>]
//
// For example:
//
//	/nix/store/abc123-openssl-3.0.12
//	/nix/store/def456-python3.11-requests-2.31.0
//	/nix/store/ghi789-perl5.38.2-FCGI-ProcManager-0.28
//
// See: https://nixos.org/manual/nix/stable/store/store-path.html
package nixstore

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "nix/store"
)

// nixStorePathRegex matches Nix store paths.
// Pattern: <32-char hash>-<name>-<version>[-<output>]
// The hash is base32 (lowercase letters and digits, no vowels except 'a').
var nixStorePathRegex = regexp.MustCompile(
	`^([0-9a-df-np-sv-z]{32})-` + // hash
		`(.+?)-` + // name (non-greedy)
		`([0-9][0-9.]*)` + // version (starts with digit, contains digits and dots)
		`(?:-(dev|lib|man|doc|info|out|bin|static|debug|py|test))?$`, // optional well-known output
)

// nixStorePathWithVersionRegex is for parsing versions that may have hyphens.
var nixStorePathWithVersionRegex = regexp.MustCompile(
	`^([0-9a-df-np-sv-z]{32})-(.+)-([0-9][0-9.]*(?:-[a-zA-Z0-9._]+)*)$`,
)

// nixStorePathWithOutputRegex is a more permissive pattern for when version parsing fails.
var nixStorePathWithOutputRegex = regexp.MustCompile(
	`^([0-9a-df-np-sv-z]{32})-(.+)$`,
)

// Metadata contains Nix-specific package metadata.
type Metadata struct {
	// PackageName is the Nix package name (e.g., "openssl", "python3.11-requests").
	PackageName string

	// PackageVersion is the package version.
	PackageVersion string

	// PackageHash is the 32-character Nix store hash.
	PackageHash string

	// PackageOutput is the output name (e.g., "dev", "lib", "man").
	// Empty for the default "out" output.
	PackageOutput string

	// OSID is the OS identifier from /etc/os-release (e.g., "nixos").
	OSID string

	// OSVersionCodename is the version codename (e.g., "vicuna").
	OSVersionCodename string

	// OSVersionID is the version ID (e.g., "24.11").
	OSVersionID string

	// CPEName is the CPE from os-release, if available.
	CPEName string
}

// Extractor implements the SCALIBR filesystem.Extractor interface
// for extracting packages from Nix store paths.
type Extractor struct {
	osInfo *OSReleaseInfo
}

// Ensure Extractor implements the filesystem.Extractor interface.
var _ filesystem.Extractor = (*Extractor)(nil)

// New creates a new Nix store extractor.
func New() filesystem.Extractor {
	return &Extractor{}
}

// Name returns the unique name of this extractor.
func (e *Extractor) Name() string { return Name }

// Version returns the extractor version.
func (e *Extractor) Version() int { return 1 }

// Requirements returns plugin requirements (none for this extractor).
func (e *Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if this file should be processed by the extractor.
// We match files within the Nix store.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	return isNixStorePath(path)
}

// isNixStorePath checks if a path is within the Nix store.
func isNixStorePath(path string) bool {
	// Match paths like /nix/store/<hash>-<name>/... or nix/store/<hash>-<name>/...
	return strings.HasPrefix(path, "/nix/store/") ||
		strings.HasPrefix(path, "nix/store/")
}

// Extract parses a Nix store path and returns package info.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	path := input.Path

	// Parse the store path
	pkgName, pkgVersion, pkgHash, pkgOutput := parseNixStorePath(path)

	if pkgHash == "" || pkgName == "" {
		// Not a valid Nix store path, skip
		return inventory.Inventory{}, nil
	}

	// Load OS release info if not cached
	if e.osInfo == nil {
		e.osInfo = loadOSRelease(input.FS)
	}

	meta := &Metadata{
		PackageName:       pkgName,
		PackageVersion:    pkgVersion,
		PackageHash:       pkgHash,
		PackageOutput:     pkgOutput,
		OSID:              e.osInfo.ID,
		OSVersionCodename: e.osInfo.VersionCodename,
		OSVersionID:       e.osInfo.VersionID,
		CPEName:           e.osInfo.CPEName,
	}

	pkg := &extractor.Package{
		Name:      pkgName,
		Version:   pkgVersion,
		PURLType:  purl.TypeNix,
		Metadata:  meta,
		Locations: []string{path},
	}

	return inventory.Inventory{Packages: []*extractor.Package{pkg}}, nil
}

// parseNixStorePath extracts name, version, hash, and output from a Nix store path.
func parseNixStorePath(path string) (name, version, hash, output string) {
	// Extract the store path component
	var storePath string
	if strings.HasPrefix(path, "/nix/store/") {
		storePath = strings.TrimPrefix(path, "/nix/store/")
	} else if strings.HasPrefix(path, "nix/store/") {
		storePath = strings.TrimPrefix(path, "nix/store/")
	} else {
		return
	}

	// Get just the directory name (first component)
	parts := strings.SplitN(storePath, "/", 2)
	dirName := parts[0]

	// Try the regex with well-known outputs first
	if matches := nixStorePathRegex.FindStringSubmatch(dirName); matches != nil {
		hash = matches[1]
		name = matches[2]
		version = matches[3]
		if len(matches) > 4 && matches[4] != "" {
			output = matches[4]
		}
		return
	}

	// Try regex that handles versions with hyphens (like 18.19.0-v8-update-1)
	if matches := nixStorePathWithVersionRegex.FindStringSubmatch(dirName); matches != nil {
		hash = matches[1]
		name = matches[2]
		version = matches[3]
		return
	}

	// Fall back to simpler parsing
	if matches := nixStorePathWithOutputRegex.FindStringSubmatch(dirName); matches != nil {
		hash = matches[1]
		remainder := matches[2]

		// Try to find version by looking for last segment starting with digit
		segments := strings.Split(remainder, "-")
		for i := len(segments) - 1; i >= 0; i-- {
			seg := segments[i]
			if len(seg) > 0 && seg[0] >= '0' && seg[0] <= '9' {
				name = strings.Join(segments[:i], "-")
				version = strings.Join(segments[i:], "-")
				return
			}
		}

		// No version found, use whole remainder as name
		name = remainder
	}

	return
}

// OSReleaseInfo contains parsed /etc/os-release data.
type OSReleaseInfo struct {
	ID              string
	VersionCodename string
	VersionID       string
	CPEName         string
	PrettyName      string
}

// loadOSRelease parses /etc/os-release for NixOS-specific info.
func loadOSRelease(fs interface{}) *OSReleaseInfo {
	info := &OSReleaseInfo{}

	// Try to read /etc/os-release
	paths := []string{"/etc/os-release", "etc/os-release"}
	var content []byte
	var err error

	for _, path := range paths {
		if reader, ok := fs.(interface{ ReadFile(string) ([]byte, error) }); ok {
			content, err = reader.ReadFile(path)
			if err == nil {
				break
			}
		}
		// Also try direct file access
		content, err = os.ReadFile(path)
		if err == nil {
			break
		}
	}

	if err != nil || len(content) == 0 {
		// Return defaults for NixOS
		return &OSReleaseInfo{
			ID: "nixos",
		}
	}

	// Parse os-release key=value pairs
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := strings.Trim(parts[1], `"'`)

		switch key {
		case "ID":
			info.ID = value
		case "VERSION_CODENAME":
			info.VersionCodename = value
		case "VERSION_ID":
			info.VersionID = value
		case "CPE_NAME":
			info.CPEName = value
		case "PRETTY_NAME":
			info.PrettyName = value
		}
	}

	return info
}

// ParseCPEName parses a CPE name from os-release.
// Example: "cpe:/o:nixos:nixos:24.11" or "cpe:2.3:o:nixos:nixos:24.11:*:*:*:*:*:*:*"
func ParseCPEName(cpeName string) (vendor, product, version string) {
	if cpeName == "" {
		return
	}

	// Handle CPE 2.2 format: cpe:/o:vendor:product:version
	if strings.HasPrefix(cpeName, "cpe:/") {
		parts := strings.Split(strings.TrimPrefix(cpeName, "cpe:/"), ":")
		if len(parts) >= 3 {
			// parts[0] is part (o, a, h)
			vendor = parts[1]
			product = parts[2]
			if len(parts) >= 4 {
				version = parts[3]
			}
		}
		return
	}

	// Handle CPE 2.3 format: cpe:2.3:part:vendor:product:version:...
	if strings.HasPrefix(cpeName, "cpe:2.3:") {
		parts := strings.Split(strings.TrimPrefix(cpeName, "cpe:2.3:"), ":")
		if len(parts) >= 4 {
			// parts[0] is part (o, a, h)
			vendor = parts[1]
			product = parts[2]
			version = parts[3]
		}
		return
	}

	return
}

// NixStorePath represents a parsed Nix store path.
type NixStorePath struct {
	Hash    string
	Name    string
	Version string
	Output  string
	Path    string
}

// Parse parses a Nix store path string.
func (p *NixStorePath) Parse(path string) bool {
	p.Path = path
	p.Name, p.Version, p.Hash, p.Output = parseNixStorePath(path)
	return p.Hash != ""
}

// PURL returns a Package URL for this Nix store path.
func (p *NixStorePath) PURL() string {
	if p.Name == "" {
		return ""
	}
	if p.Version != "" {
		return fmt.Sprintf("pkg:nix/%s@%s", p.Name, p.Version)
	}
	return fmt.Sprintf("pkg:nix/%s", p.Name)
}

// ListNixStorePackages lists packages in the Nix store directory.
func ListNixStorePackages(storeDir string) ([]NixStorePath, error) {
	if storeDir == "" {
		storeDir = "/nix/store"
	}

	entries, err := os.ReadDir(storeDir)
	if err != nil {
		return nil, fmt.Errorf("read nix store: %w", err)
	}

	var packages []NixStorePath
	seen := make(map[string]bool)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		path := filepath.Join(storeDir, entry.Name())
		var pkg NixStorePath
		if pkg.Parse(path) {
			// Dedupe by name+version
			key := pkg.Name + "@" + pkg.Version
			if !seen[key] {
				seen[key] = true
				packages = append(packages, pkg)
			}
		}
	}

	return packages, nil
}
