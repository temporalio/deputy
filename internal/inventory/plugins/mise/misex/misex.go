// Package misex extracts dev-toolchain dependencies from mise-en-place
// configuration (mise.toml, .mise.toml, .config/mise/config.toml, and related
// drop-ins). The legacy asdf .tool-versions format is handled by the separate
// asdfx extractor, mirroring OSV-SCALIBR's runtime/mise and runtime/asdf split.
//
// This is a Deputy custom OSV-SCALIBR filesystem extractor. OSV-SCALIBR ships an
// upstream runtime/mise extractor, but it is inventory-only (no [settings], no
// backend/fuzzy awareness) and is not present in the SCALIBR version Deputy
// currently pins. This extractor emits the same pkg:mise PURL type as upstream
// for forward-compatibility, while carrying the extra metadata (backend,
// canonical backend PURL, fuzzy classification) that Deputy's pin and hardening
// features rely on.
package misex

import (
	"context"
	"io"
	"log/slog"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"

	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/purlx"
)

const (
	// Name is the internal plugin identifier.
	Name = "mise/tools"
)

// Extractor implements an OSV-SCALIBR filesystem extractor for mise.toml configs.
type Extractor struct{}

// New returns a new mise extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name returns the plugin name as understood by Deputy.
func (Extractor) Name() string { return Name }

// Version returns the plugin version; Deputy uses 0 for internal plugins.
func (Extractor) Version() int { return 0 }

// Requirements declares required capabilities; mise scanning is filesystem-only.
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired limits extraction to TOML-format mise configuration files.
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	format, ok := mise.IsConfigPath(api.Path())
	return ok && format == mise.FormatTOML
}

// Extract parses a mise.toml file and returns its tool dependencies as pkg:mise
// packages.
func (Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input == nil || input.Reader == nil {
		return inventory.Inventory{}, nil
	}
	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}

	cfg, err := mise.Parse(input.Path, data)
	if err != nil {
		// Malformed config shouldn't abort the whole scan; log and skip.
		slog.WarnContext(ctx, "mise parse error", "path", input.Path, "error", err)
		return inventory.Inventory{}, nil
	}

	// Best-effort: load the sibling mise.lock to enrich entries with the exact
	// locked version and per-platform integrity checksums.
	lock, err := mise.LoadSiblingLock(input.FS, input.Path)
	if err != nil {
		slog.WarnContext(ctx, "mise lockfile load error", "path", mise.LockfilePath(input.Path), "error", err)
	}

	// Which names the config's declarations claim, so lock lookup does not
	// lend one declaration's entry to another whose short name collides.
	claims := mise.NameClaims(cfg.Tools)

	var pkgs []*extractor.Package
	for _, tool := range cfg.Tools {
		for _, version := range tool.Versions {
			if version == "" {
				continue
			}
			md := mise.MetadataFor(tool, version, cfg.Format)
			enrichFromLock(md, lock, tool, version, claims)
			pkgVersion := version
			if md.LockedVersion != "" {
				pkgVersion = md.LockedVersion
			}
			pkgs = append(pkgs, &extractor.Package{
				Name:      tool.Key,
				Version:   pkgVersion,
				PURLType:  purlx.TypeMise,
				Locations: []string{input.Path},
				Metadata:  md,
			})
		}
	}
	if len(pkgs) == 0 {
		return inventory.Inventory{}, nil
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

// enrichFromLock fills the locked version and per-platform checksums on md from
// a sibling lockfile entry, when one matches. claims carries how many of the
// config's declarations could own each name, so an entry another declaration
// might own is not borrowed for this one.
func enrichFromLock(md *mise.Metadata, lock *mise.Lockfile, tool mise.ToolSpec, version string, claims map[string]int) {
	lt := lock.Lookup(tool, version, claims)
	if lt == nil {
		return
	}
	md.LockedVersion = lt.Version
	md.BackendPURL = mise.BackendPURL(tool.Backend, tool.Name, lt.Version)
	md.Checksums = lt.Checksums()
	md.Platforms = lt.Platforms
}
