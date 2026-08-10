package mise

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/BurntSushi/toml"
)

// Lockfile is a parsed mise.lock file. mise writes it next to a mise.toml when
// `[settings] lockfile = true`, recording the exact resolved version of each
// tool plus per-platform integrity metadata (checksums/size/url).
//
// See https://mise.jdx.dev/dev-tools/mise-lock.html for the format.
type Lockfile struct {
	// Tools maps a tool name to its locked entries. A tool may have more than
	// one entry (e.g. multiple requested versions), so the value is a slice,
	// matching the [[tools.<name>]] array-of-tables structure.
	Tools map[string][]LockedTool
}

// LockedTool is a single locked tool entry from a mise.lock file.
type LockedTool struct {
	// Version is the exact resolved version (e.g. "20.11.0").
	Version string `toml:"version"`
	// Backend is the full backend identifier mise resolved the tool through
	// (e.g. "core:node", "aqua:BurntSushi/ripgrep").
	Backend string `toml:"backend"`
	// Options carries backend-specific artifact identifiers, when present.
	Options map[string]any `toml:"options"`
	// Platforms maps an "os-arch" key (e.g. "linux-x64", "macos-arm64") to its
	// integrity metadata.
	Platforms map[string]LockedPlatform `toml:"platforms"`
}

// LockedPlatform holds per-platform integrity metadata for a locked tool.
type LockedPlatform struct {
	// Checksum is a "sha256:..." or "blake3:..." digest of the downloaded asset.
	Checksum string `toml:"checksum"`
	// Size is the asset size in bytes.
	Size int64 `toml:"size"`
	// URL is the asset download URL.
	URL string `toml:"url"`
}

// lockfileTOML mirrors the on-disk structure: a top-level [tools] table whose
// entries are arrays of tables. Each entry is decoded generically because real
// mise.lock files key per-platform data with a single quoted dotted key —
// [tools."<key>"."platforms.linux-x64"] — rather than a nested platforms table,
// and a struct field can't capture those dynamic keys.
type lockfileTOML struct {
	Tools map[string][]map[string]any `toml:"tools"`
}

// ParseLock parses mise.lock content. Tool entries with no version are dropped.
func ParseLock(path string, data []byte) (*Lockfile, error) {
	var parsed lockfileTOML
	if err := toml.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("mise: parsing lockfile %s: %w", path, err)
	}
	lf := &Lockfile{Tools: make(map[string][]LockedTool, len(parsed.Tools))}
	for name, entries := range parsed.Tools {
		kept := make([]LockedTool, 0, len(entries))
		for _, raw := range entries {
			lt := lockedToolFromMap(raw)
			if lt.Version == "" {
				continue
			}
			kept = append(kept, lt)
		}
		if len(kept) > 0 {
			lf.Tools[name] = kept
		}
	}
	return lf, nil
}

// LoadSiblingLock reads and parses the mise.lock next to a TOML config. It
// returns nil when the config format has no sibling lockfile path or when the
// lockfile is absent.
func LoadSiblingLock(fsys fs.FS, configPath string) (*Lockfile, error) {
	lockPath := LockfilePath(configPath)
	if lockPath == "" || fsys == nil {
		return nil, nil
	}
	data, err := fs.ReadFile(fsys, lockPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("mise: reading lockfile %s: %w", lockPath, err)
	}
	return ParseLock(lockPath, data)
}

// lockedToolFromMap builds a LockedTool from a generically decoded entry,
// extracting per-platform integrity data from either the flat dotted form
// ("platforms.<os-arch>" keys, as real mise emits) or a nested "platforms"
// table.
func lockedToolFromMap(raw map[string]any) LockedTool {
	lt := LockedTool{
		Version: stringField(raw["version"]),
		Backend: stringField(raw["backend"]),
	}
	if opts, ok := raw["options"].(map[string]any); ok {
		lt.Options = opts
	}

	platforms := map[string]LockedPlatform{}
	// Nested form: [tools.<name>.platforms.<os-arch>]
	if nested, ok := raw["platforms"].(map[string]any); ok {
		for plat, v := range nested {
			if pm, ok := v.(map[string]any); ok {
				platforms[plat] = platformFromMap(pm)
			}
		}
	}
	// Flat dotted form: [tools."<name>"."platforms.<os-arch>"]
	for key, v := range raw {
		plat, ok := strings.CutPrefix(key, "platforms.")
		if !ok || plat == "" {
			continue
		}
		if pm, ok := v.(map[string]any); ok {
			platforms[plat] = platformFromMap(pm)
		}
	}
	if len(platforms) > 0 {
		lt.Platforms = platforms
	}
	return lt
}

// platformFromMap extracts per-platform integrity fields from a decoded table.
func platformFromMap(m map[string]any) LockedPlatform {
	p := LockedPlatform{
		Checksum: stringField(m["checksum"]),
		URL:      stringField(m["url"]),
	}
	if sz, ok := m["size"].(int64); ok {
		p.Size = sz
	}
	return p
}

// stringField returns v as a string when it is one, else "".
func stringField(v any) string {
	s, _ := v.(string)
	return s
}

// Locked returns the locked entry for a tool name and exact version, or nil if
// the lockfile has no matching entry.
func (lf *Lockfile) Locked(name, version string) *LockedTool {
	if lf == nil {
		return nil
	}
	for i := range lf.Tools[name] {
		if lf.Tools[name][i].Version == version {
			return &lf.Tools[name][i]
		}
	}
	return nil
}

// First returns the first locked entry for a tool name, or nil.
func (lf *Lockfile) First(name string) *LockedTool {
	if lf == nil || len(lf.Tools[name]) == 0 {
		return nil
	}
	return &lf.Tools[name][0]
}

// Sole returns the locked entry for a tool name only when exactly one entry is
// present. It is useful when a declared fuzzy version does not equal any locked
// version string; with multiple lock entries there is no safe inferred match.
func (lf *Lockfile) Sole(name string) *LockedTool {
	if lf == nil || len(lf.Tools[name]) != 1 {
		return nil
	}
	return &lf.Tools[name][0]
}

// Lookup finds the locked entry that best matches a parsed tool spec at a
// requested version. It prefers an exact version match (by the tool's short name
// then its raw key), and otherwise falls back to the sole locked entry under
// either name, which covers a fuzzy declared version that won't equal any
// locked version string. Returns nil when nothing matches.
//
// claimedKeys lists the tool keys the surrounding config declares, so a lock
// entry keyed by a tool's short name is not borrowed when a different
// declaration owns that name. A config can declare both "npm:node" and node as
// independent tools with independent lock entries; without this, the
// backend-qualified spec matches on its stripped name and is enriched with the
// other tool's version, which after a fix reports the freshly updated tool at
// the old vulnerable version. Pass nil when no config context is available.
func (lf *Lockfile) Lookup(spec ToolSpec, version string, claimedKeys map[string]bool) *LockedTool {
	if lf == nil {
		return nil
	}
	// A name owned by another declaration is not this spec's to match.
	usable := func(name string) bool {
		return name == spec.Key || !claimedKeys[name]
	}
	for _, name := range [...]string{spec.Name, spec.Key} {
		if usable(name) {
			if lt := lf.Locked(name, version); lt != nil {
				return lt
			}
		}
	}
	for _, name := range [...]string{spec.Name, spec.Key} {
		if usable(name) {
			if lt := lf.Sole(name); lt != nil {
				return lt
			}
		}
	}
	return nil
}

// Checksums returns the per-platform checksums for a locked tool, keyed by the
// "os-arch" platform string. Entries without a checksum are omitted.
func (t *LockedTool) Checksums() map[string]string {
	if t == nil || len(t.Platforms) == 0 {
		return nil
	}
	out := make(map[string]string, len(t.Platforms))
	for plat, p := range t.Platforms {
		if p.Checksum != "" {
			out[plat] = p.Checksum
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
