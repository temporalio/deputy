package mise

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
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

// NameClaims counts, for every name a lockfile entry could be keyed by, how
// many of a config's declarations could own an entry under it. Each
// declaration claims its literal key and, when a backend prefix makes them
// differ, its backend-stripped name: a legacy `[[tools.foo]]` entry is as
// plausibly "npm:foo"'s as it is "ubi:foo"'s or a bare foo's.
//
// A count above one means no single declaration owns the name. That is the one
// definition of ownership shared by both readers of a lockfile: [Lockfile.Lookup]
// refuses to enrich from a contested entry, and remediation refuses to prune
// one. Deriving both from this count keeps them from drifting, which they did
// when enrichment tracked literal keys while pruning tracked stripped names,
// leaving an entry that pruning preserved as ambiguous free to be borrowed by
// enrichment on the next scan.
func NameClaims(tools []ToolSpec) map[string]int {
	claims := make(map[string]int, len(tools)*2)
	for _, tool := range tools {
		claims[tool.Key]++
		if tool.Name != "" && tool.Name != tool.Key {
			claims[tool.Name]++
		}
	}
	return claims
}

// ConfigsSharingLock returns every mise config that locks into the same
// lockfile as configPath, configPath included, in lexical order. A mise
// directory's config.toml and all of its conf.d drop-ins write to one
// mise.lock: verified against mise 2026.7.3, which reports
// ".config/mise/mise.lock" as the lock target for a tool declared only in
// ".config/mise/conf.d/b.toml".
//
// The set is derived from [LockfilePath] rather than listed here, so a change
// to mise's lockfile naming moves the sharing rule with it. Membership is
// decided on the file a config's lockfile path resolves to, not on the path
// itself, because a lockfile may be a symlink and mise reads through it: with
// "a/mise.lock" and "b/mise.lock" both linked to one "shared.lock", mise
// 2026.7.3 resolves each directory's declarations against that one file. A fix
// publishes its edit to the link target too, so counting only the declarations
// beside the link would delete integrity metadata another directory still
// needs.
//
// The candidates are the lockfile's own directory and the conf.d beside it,
// the only two a lexical lock path can come from. When the lockfile is a
// symlink its claimants can be anywhere, so the tree is walked instead; that
// costs a traversal per config, which is why it is spent only on the configs
// that are actually linked. A config whose lockfile is a regular file and
// which some directory outside those two links into is the case this does not
// see.
//
// An empty result means configPath has no lockfile at all (a .tool-versions
// file, say). A read error other than a missing conf.d is returned, because a
// config that cannot be listed is a config whose declarations cannot be
// counted.
func ConfigsSharingLock(fsys fs.FS, configPath string) ([]string, error) {
	lockPath := LockfilePath(configPath)
	if lockPath == "" {
		return nil, nil
	}
	if fsys == nil {
		return nil, fmt.Errorf("mise: no filesystem to resolve the configs sharing %s", lockPath)
	}
	target, linked, err := ResolveLinkedPath(fsys, lockPath)
	if err != nil {
		return nil, err
	}
	candidates, err := lockSharingCandidates(fsys, lockPath, linked)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var shared []string
	for _, candidate := range candidates {
		if _, ok := IsConfigPath(candidate); !ok {
			continue
		}
		candidateLock := LockfilePath(candidate)
		if candidateLock == "" {
			continue
		}
		candidateTarget, _, err := ResolveLinkedPath(fsys, candidateLock)
		if err != nil {
			return nil, fmt.Errorf("resolving the lockfile of %s: %w", candidate, err)
		}
		if candidateTarget != target {
			continue
		}
		if _, dup := seen[candidate]; dup {
			continue
		}
		seen[candidate] = struct{}{}
		shared = append(shared, candidate)
	}
	// configPath itself belongs in the set even when the walk above missed it,
	// so a caller never decides ownership without the config it is editing.
	if clean := path.Clean(configPath); len(shared) > 0 {
		if _, ok := seen[clean]; !ok {
			shared = append(shared, clean)
		}
	}
	slices.Sort(shared)
	return shared, nil
}

// lockSharingCandidates returns the paths that might be configs locking into
// lockPath's target. When the lockfile sits at its own path, only its
// directory and the conf.d beside it can send a config there, so those are
// listed. A linked lockfile is shared by whoever links to it, which no
// directory listing can name, so the tree is walked for every config in it.
// The caller decides membership by resolving each candidate's own lockfile, so
// a candidate listed here is a maybe, never a member.
func lockSharingCandidates(fsys fs.FS, lockPath string, linked bool) ([]string, error) {
	if linked {
		return allConfigPaths(fsys)
	}
	lockDir := path.Dir(lockPath)
	var out []string
	for _, dir := range [...]string{lockDir, path.Join(lockDir, "conf.d")} {
		entries, err := fs.ReadDir(fsys, dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("listing %s: %w", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			out = append(out, path.Join(dir, entry.Name()))
		}
	}
	return out, nil
}

// allConfigPaths walks fsys for every mise config in it. A directory that
// cannot be read is an error rather than an omission: a config it hides is one
// whose declarations would have contested a lock entry, and the caller reads
// the error as "ownership unknown" and leaves the entry alone.
func allConfigPaths(fsys fs.FS) ([]string, error) {
	var out []string
	err := fs.WalkDir(fsys, ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if _, ok := IsConfigPath(p); ok {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing the configs that could share a lockfile: %w", err)
	}
	return out, nil
}

// maxLinkHops bounds symlink resolution so a cyclic or absurdly deep chain
// ends in an error instead of looping. The limit is generous next to any real
// repository layout; the operating system's own limit is typically far lower.
const maxLinkHops = 32

// ResolveLinkedPath returns the path relPath ultimately names in fsys,
// following an in-repository symlink chain, and reports whether any link was
// followed. It is the one answer to "which file is this really", shared by the
// reader that decides who owns a lockfile and the writer that publishes an
// edit to one, so the file a claim is counted against is the file the edit
// lands on.
//
// Each hop is read through fsys, and a target that is absolute or climbs out
// of the tree is refused rather than followed, so resolution cannot be talked
// into naming a file outside it. A path that does not exist resolves to
// itself: there is no link to follow, and a caller may be about to create it.
// A filesystem that cannot report links resolves every path to itself, which
// is the reading it would have had before links were considered at all.
func ResolveLinkedPath(fsys fs.FS, relPath string) (target string, linked bool, err error) {
	reader, ok := fsys.(fs.ReadLinkFS)
	if !ok {
		return relPath, false, nil
	}
	for range maxLinkHops {
		info, err := reader.Lstat(relPath)
		if errors.Is(err, fs.ErrNotExist) {
			return relPath, linked, nil
		}
		if err != nil {
			return "", false, fmt.Errorf("stat %s: %w", relPath, err)
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			return relPath, linked, nil
		}
		text, err := reader.ReadLink(relPath)
		if err != nil {
			return "", false, fmt.Errorf("reading link %s: %w", relPath, err)
		}
		if filepath.IsAbs(text) {
			return "", false, fmt.Errorf("refusing to follow %s: it links to the absolute path %s", relPath, text)
		}
		next := path.Join(path.Dir(relPath), filepath.ToSlash(text))
		if next == ".." || strings.HasPrefix(next, "../") {
			return "", false, fmt.Errorf("refusing to follow %s: it links outside the repository via %s", relPath, text)
		}
		relPath, linked = next, true
	}
	return "", false, fmt.Errorf("resolving %s: more than %d symbolic links", relPath, maxLinkHops)
}

// LockClaims counts, over every config that shares configPath's lockfile, how
// many declarations could own a lock entry keyed by a given name. It is
// [NameClaims] widened to the scope the lockfile actually has.
//
// Counting one fragment is not enough. With ".config/mise/conf.d/a.toml"
// declaring "npm:foo", "b.toml" beside it declaring "ubi:foo", and a legacy
// [[tools.foo]] entry in the mise.lock they share, a.toml alone shows a single
// claimant for foo. Enrichment then lends that entry to npm:foo and to ubi:foo
// both, and remediation prunes it while fixing either one, discarding
// integrity metadata for a declaration nobody edited.
//
// An error means ownership could not be established, and a caller must then
// treat every name as contested: prune nothing beyond the exact key, enrich
// from nothing. An unparsable sharing config is such an error, because its
// declarations are exactly the ones that would have contested a name.
func LockClaims(fsys fs.FS, configPath string) (map[string]int, error) {
	shared, err := ConfigsSharingLock(fsys, configPath)
	if err != nil {
		return nil, err
	}
	claims := make(map[string]int)
	for _, cfgPath := range shared {
		data, err := fs.ReadFile(fsys, cfgPath)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", cfgPath, err)
		}
		cfg, err := Parse(cfgPath, data)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", cfgPath, err)
		}
		for name, n := range NameClaims(cfg.Tools) {
			claims[name] += n
		}
	}
	return claims, nil
}

// Lookup finds the locked entry that best matches a parsed tool spec at a
// requested version. It prefers an exact version match (by the tool's short name
// then its raw key), and otherwise falls back to the sole locked entry under
// either name, which covers a fuzzy declared version that won't equal any
// locked version string. Returns nil when nothing matches.
//
// claims comes from [LockClaims] over every config sharing the lockfile, so a
// lock entry is not borrowed when another declaration could own the name it is
// keyed by. A config can declare both "npm:node" and node, or both "npm:foo"
// and "ubi:foo", as independent tools with independent lock entries; without
// this, a backend-qualified spec matches on its stripped name and is enriched
// with another tool's version, which after a fix reports the freshly updated
// tool at the old vulnerable version. Pass nil when no config context is
// available.
func (lf *Lockfile) Lookup(spec ToolSpec, version string, claims map[string]int) *LockedTool {
	if lf == nil {
		return nil
	}
	names := LockCandidateNames(spec)
	for _, name := range names {
		if MayMatchLockName(spec, name, claims) {
			if lt := lf.Locked(name, version); lt != nil {
				return lt
			}
		}
	}
	for _, name := range names {
		if MayBorrowSoleLockEntry(name, claims) {
			if lt := lf.Sole(name); lt != nil {
				return lt
			}
		}
	}
	return nil
}

// LockCandidateNames returns the mise.lock table keys a declaration could be
// recorded under, short name first because real lockfiles usually key entries
// that way. Both readers of a lockfile, inventory enrichment and pin
// discovery, walk this list, so neither can grow a candidate the other does
// not know to gate.
func LockCandidateNames(spec ToolSpec) []string {
	if spec.Key == "" || spec.Name == spec.Key {
		return []string{spec.Name}
	}
	return []string{spec.Name, spec.Key}
}

// MayMatchLockName reports whether spec may take a lock entry keyed by name
// whose version is exactly the one spec requests. A spec always owns its
// literal key here: an entry keyed by exactly what the declaration spells, at
// exactly the version it spells, is that declaration's however many others
// share the name. Any other name is only this spec's when no second
// declaration claims it, since the spec itself accounts for one claim.
//
// claims comes from [LockClaims]. A nil map records no claims and gates
// nothing, which is what a caller with no config context gets.
func MayMatchLockName(spec ToolSpec, name string, claims map[string]int) bool {
	return name == spec.Key || claims[name] <= 1
}

// MayBorrowSoleLockEntry reports whether the sole entry keyed by name may be
// handed to a declaration that matched no version. This fallback is a guess,
// so it needs an uncontested claim even for a declaration's literal key: two
// configs sharing a lockfile can spell the same key, and the count in claims
// spans all of them. Lending one of them the other's entry reports a version
// the declaration does not ask for, which is how a fix applied to one fragment
// reads as the vulnerable version coming back.
func MayBorrowSoleLockEntry(name string, claims map[string]int) bool {
	return claims[name] <= 1
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
