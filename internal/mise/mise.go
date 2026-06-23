// Package mise parses mise-en-place (https://mise.jdx.dev) configuration so
// Deputy can inventory, scan, pin, and harden the dev toolchains mise manages.
//
// mise installs tools (node, go, python, terraform, …) from many backends —
// aqua, ubi/GitHub releases, cargo, npm, pipx, go, gem, and asdf plugins — which
// makes its config a supply-chain surface like any package manager: a floating
// version resolves to the newest matching release at install time. This package
// is the shared foundation used by the inventory extractor, the pin strategy,
// and the hardening audit.
//
// Parsing is offline and performs no network or filesystem traversal beyond the
// bytes it is handed; discovery and rewriting live in the callers.
package mise

import (
	"path"
	"regexp"
	"strings"
)

// Format identifies the on-disk configuration syntax.
type Format string

const (
	// FormatTOML is the native mise.toml / .mise.toml TOML format.
	FormatTOML Format = "toml"

	// FormatToolVersions is the legacy asdf-compatible .tool-versions format.
	FormatToolVersions Format = "tool-versions"
)

// configBasenames contains the exact mise config basenames. Env/local variants
// are recognized by [isMiseTOMLBasename].
var configBasenames = map[string]Format{
	"mise.toml":      FormatTOML,
	".mise.toml":     FormatTOML,
	".tool-versions": FormatToolVersions,
}

// configSuffixes matches nested config locations regardless of leading
// directory, e.g. .config/mise/config.toml or mise/config.toml.
var configSuffixes = []string{
	".config/mise/config.toml",
	".config/mise.toml",
	".mise/config.toml",
	"mise/config.toml",
}

// IsConfigPath reports whether p (a slash-separated path) is a recognized mise
// configuration file, returning its format. It matches both the flat basenames
// (mise.toml, .tool-versions, …) and the nested .config/mise/config.toml style
// locations, including files under a .config/mise/conf.d/ directory.
func IsConfigPath(p string) (Format, bool) {
	p = strings.TrimPrefix(path.Clean(strings.ReplaceAll(p, "\\", "/")), "./")
	base := path.Base(p)
	if f, ok := configBasenames[base]; ok {
		return f, true
	}
	if isMiseTOMLBasename(base) {
		return FormatTOML, true
	}
	for _, suffix := range configSuffixes {
		if p == suffix || strings.HasSuffix(p, "/"+suffix) {
			return FormatTOML, true
		}
	}
	if isNestedMiseConfigPath(p) {
		return FormatTOML, true
	}
	// conf.d drop-ins: any *.toml inside a mise/conf.d directory.
	if dir := path.Dir(p); strings.HasSuffix(base, ".toml") && (dir == "mise/conf.d" || strings.HasSuffix(dir, "/mise/conf.d")) {
		return FormatTOML, true
	}
	return "", false
}

// isMiseTOMLBasename reports whether base is a root-level mise TOML config
// filename, including env-specific variants such as mise.test.toml.
func isMiseTOMLBasename(base string) bool {
	rest, ok := strings.CutPrefix(base, "mise.")
	if !ok {
		rest, ok = strings.CutPrefix(base, ".mise.")
	}
	if !ok || !strings.HasSuffix(rest, ".toml") {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(rest, ".toml"), ".")
	switch len(parts) {
	case 1:
		return parts[0] == "local" || validMiseEnv(parts[0])
	case 2:
		return validMiseEnv(parts[0]) && parts[1] == "local"
	default:
		return false
	}
}

// isNestedMiseConfigPath reports whether p is a config.*.toml file in one of
// mise's nested config directories.
func isNestedMiseConfigPath(p string) bool {
	base := path.Base(p)
	dir := path.Dir(p)
	if !strings.HasPrefix(base, "config.") || !strings.HasSuffix(base, ".toml") {
		return false
	}
	if dir != "mise" && dir != ".mise" && dir != ".config/mise" &&
		!strings.HasSuffix(dir, "/mise") && !strings.HasSuffix(dir, "/.mise") && !strings.HasSuffix(dir, "/.config/mise") {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(base, "config."), ".toml"), ".")
	switch len(parts) {
	case 1:
		return parts[0] == "local" || validMiseEnv(parts[0])
	case 2:
		return validMiseEnv(parts[0]) && parts[1] == "local"
	default:
		return false
	}
}

// validMiseEnv accepts a single environment name segment from a mise config
// filename. "local" is reserved for developer-local overrides.
func validMiseEnv(env string) bool {
	return env != "" && env != "local" && !strings.ContainsAny(env, `/\`)
}

// IsLocalConfig reports whether p is a mise.local.toml-style override, which by
// convention is developer-local and not committed to shared repositories.
func IsLocalConfig(p string) bool {
	base := strings.ToLower(path.Base(strings.ReplaceAll(p, "\\", "/")))
	return base == "mise.local.toml" || base == ".mise.local.toml" ||
		strings.HasSuffix(base, ".local.toml")
}

// LockfilePath returns the mise.lock path that sits next to a TOML config file.
// For .tool-versions or non-TOML configs it returns an empty string, since mise
// only writes lockfiles alongside .toml configs.
func LockfilePath(configPath string) string {
	cp := strings.ReplaceAll(configPath, "\\", "/")
	if !strings.HasSuffix(cp, ".toml") {
		return ""
	}
	return strings.TrimSuffix(cp, ".toml") + ".lock"
}

// knownBackends lists mise backend prefixes used in [tools] keys (e.g.
// "npm:prettier"). The list covers documented backends Deputy needs to split
// for metadata and routing.
var knownBackends = map[string]struct{}{
	"core": {}, "asdf": {}, "aqua": {}, "ubi": {}, "vfox": {},
	"cargo": {}, "conda": {}, "dotnet": {}, "forgejo": {}, "gem": {},
	"github": {}, "gitlab": {}, "go": {}, "http": {}, "npm": {},
	"pipx": {}, "pip": {}, "s3": {}, "spm": {},
}

// SplitBackend separates a [tools] key into its backend prefix and tool name.
// "npm:prettier" -> ("npm", "prettier"); "node" -> ("", "node"). Only the first
// ":" is treated as a backend separator, and only when the prefix is a known
// backend, so tool names that legitimately contain a colon are left intact.
//
// Any trailing mise tool-options group ("[exe=gh]", "[provider=gitlab]") is
// stripped from the returned name so callers resolving an owner/repo or a
// registry coordinate never see option syntax. Use [ToolOptions] to read the
// options themselves.
func SplitBackend(key string) (backend, name string) {
	key = strings.TrimSpace(key)
	if pre, rest, found := strings.Cut(key, ":"); found {
		if _, ok := knownBackends[strings.ToLower(pre)]; ok {
			return strings.ToLower(pre), stripToolOptions(rest)
		}
	}
	return "", stripToolOptions(key)
}

// stripToolOptions removes a trailing mise tool-options group ("[k=v,...]") from
// a tool name. mise accepts options in both .tool-versions tokens and config
// keys, e.g. "ubi:cli/cli[exe=gh]" or "ubi:owner/repo[provider=gitlab]".
func stripToolOptions(name string) string {
	if i := strings.IndexByte(name, '['); i >= 0 {
		return strings.TrimSpace(name[:i])
	}
	return strings.TrimSpace(name)
}

// ToolOptions parses a trailing mise tool-options group ("[k=v,k2=v2]") from a
// tool key or name, returning the options with lowercased keys. A bare flag
// ("[foo]") maps to an empty value. Returns nil when there are none. This is
// the inline-key form; the inline-table form (`{ provider = "gitlab" }`) is
// captured separately during parsing.
func ToolOptions(key string) map[string]string {
	i := strings.IndexByte(key, '[')
	if i < 0 {
		return nil
	}
	j := strings.LastIndexByte(key, ']')
	if j <= i+1 {
		return nil
	}
	opts := map[string]string{}
	for _, kv := range strings.Split(key[i+1:j], ",") {
		k, v, _ := strings.Cut(kv, "=")
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			opts[k] = strings.TrimSpace(v)
		}
	}
	if len(opts) == 0 {
		return nil
	}
	return opts
}

// exactVersionRe matches a fully specified version core: major.minor.patch
// appearing anywhere in the string. It is intentionally a "contains" match (not
// anchored) so it also recognizes distribution-prefixed runtime versions such
// as mise's Java strings ("temurin-21.0.5+11.0.LTS"). mise treats a partial
// version like "20" or "1.7" — or a distribution major like "temurin-21" — as a
// fuzzy request that resolves to the newest matching release, and those have no
// major.minor.patch core, so they are correctly excluded. Ranges and selectors
// are filtered out before this check.
var exactVersionRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

// fuzzyChannels are well-known non-numeric channels that always resolve to a
// moving target.
var fuzzyChannels = map[string]struct{}{
	"latest": {}, "lts": {}, "stable": {}, "current": {}, "system": {}, "": {},
}

// IsExactVersion reports whether a requested version string pins a single,
// maximally specified release. Exact pins have a full major.minor.patch core
// (e.g. "22.5.0", "v1.24.3", "temurin-21.0.5+11"). Anything less specific —
// channels ("latest", "lts"), partial versions ("20", "1.7", "33.1"), ranges,
// and prefix/ref selectors — returns false. It is intentionally conservative:
// a partial version like "33.1" can still float if the registry later adds a
// more specific release, so for a supply-chain pin check it is treated as not
// fully pinned. Use [IsConcreteVersion] to accept a resolver's authoritative
// output (which may legitimately be partial for tools like protobuf).
func IsExactVersion(v string) bool {
	if !IsConcreteVersion(v) {
		return false
	}
	return exactVersionRe.MatchString(strings.TrimSpace(v))
}

// concreteVersionRe matches at least a major.minor numeric core, so a resolved
// partial-but-final version like protobuf's "33.1" qualifies while a bare
// major-only prefix like "20" does not.
var concreteVersionRe = regexp.MustCompile(`\d+\.\d+`)

// IsConcreteVersion reports whether v names a specific resolved version — as
// returned by `mise latest` — rather than a channel, range, selector, or a bare
// major-only prefix. Unlike [IsExactVersion] it accepts partial-but-final forms
// (e.g. protobuf's "33.1"), since that is the most specific version such a tool
// publishes, but it still requires at least a major.minor core so under-specified
// requests like "20" are rejected.
func IsConcreteVersion(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	if _, ok := fuzzyChannels[strings.ToLower(v)]; ok {
		return false
	}
	if strings.ContainsAny(v, "^~*<>= ") || strings.Contains(v, "..") {
		return false
	}
	if strings.HasPrefix(v, "prefix:") || strings.HasPrefix(v, "ref:") || strings.HasPrefix(v, "sub-") {
		return false
	}
	return concreteVersionRe.MatchString(v)
}
