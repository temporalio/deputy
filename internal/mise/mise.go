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
	"slices"
	"strconv"
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

// miseDirName is the canonical name of a mise config directory, and the stem
// mise gives the lockfile it keeps there. The directory may be written with a
// leading dot (".mise"), but the lockfile inside it never is.
const miseDirName = "mise"

// isMiseConfigDir reports whether dir is one of mise's config directories, the
// "mise" or ".mise" holding a config.toml or a conf.d. The dotted and undotted
// spellings are the same directory to mise, so both must map to the same
// lockfile name.
func isMiseConfigDir(dir string) bool {
	base := path.Base(dir)
	return base == miseDirName || base == "."+miseDirName
}

// LockfilePath returns the lockfile mise associates with a TOML config file.
// For .tool-versions or non-TOML configs it returns an empty string, since mise
// only locks .toml configs.
//
// The name is not simply the config's own name with a .lock suffix. Verified
// against mise 2026.7.3 (`mise lock --dry-run` reports its target, and
// resolution honors only that file):
//
//	mise.toml                           -> mise.lock
//	.mise.toml                          -> mise.lock       (not .mise.lock)
//	mise.production.toml                -> mise.production.lock
//	.mise.local.toml                    -> mise.local.lock
//	.config/mise.toml                   -> .config/mise.lock
//	.config/mise/config.toml            -> .config/mise/mise.lock
//	.mise/config.toml                   -> .mise/mise.lock
//	.config/mise/config.production.toml -> .config/mise/mise.production.lock
//	.mise/config.local.toml             -> .mise/mise.local.lock
//	.config/mise/conf.d/tools.toml      -> .config/mise/mise.lock
//
// So: a leading dot is dropped from the config's basename; inside a mise
// directory the config's "config" stem is renamed to "mise" while any
// env/local segments carry over; and conf.d drop-ins share the lockfile of the
// mise directory they belong to. Getting this wrong is not cosmetic: pointing
// at .mise.lock or .mise/config.lock reads and writes a file mise ignores
// entirely, leaving the real lock stale.
func LockfilePath(configPath string) string {
	cp := strings.ReplaceAll(configPath, "\\", "/")
	if !strings.HasSuffix(cp, ".toml") {
		return ""
	}
	dir, base := path.Split(cp)
	dir = path.Clean(dir)

	// conf.d drop-ins are merged into the enclosing mise directory, which owns
	// the lockfile for all of them.
	if path.Base(dir) == "conf.d" && isMiseConfigDir(path.Dir(dir)) {
		return path.Join(path.Dir(dir), "mise.lock")
	}
	// <...>/mise/config[.env][.local].toml is the directory's config; its lock
	// is named for the directory, keeping the basename's trailing segments.
	if rest, ok := strings.CutPrefix(base, "config"); ok && strings.HasPrefix(rest, ".") && isMiseConfigDir(dir) {
		return path.Join(dir, miseDirName+strings.TrimSuffix(rest, ".toml")+".lock")
	}
	// Otherwise the lock sits beside the config under the config's own name
	// with any leading dot dropped.
	base = strings.TrimPrefix(base, ".")
	if !strings.HasSuffix(base, ".toml") {
		return ""
	}
	return path.Join(dir, strings.TrimSuffix(base, ".toml")+".lock")
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
	if hasAnyPrefix(v, selectorWrapperPrefixes) || hasAnyPrefix(v, unversionedPrefixes) {
		return false
	}
	return concreteVersionRe.MatchString(v)
}

// selectorWrapperPrefixes are the mise request prefixes that wrap another
// version request rather than naming a release themselves: "prefix:20" asks
// for the newest release under 20 and "sub-1:20.11" for one release below
// 20.11, so a wrapped request constrains resolution exactly as much as the
// request it wraps.
var selectorWrapperPrefixes = []string{"prefix:", "sub-"}

// unversionedPrefixes are the mise request prefixes that point at something
// that is not a release at all: a git ref or a local checkout. A declaration
// using one names no version, so its text says nothing about which release
// gets installed.
var unversionedPrefixes = []string{"ref:", "path:", "file:"}

// hasAnyPrefix reports whether s starts with any of prefixes. It keeps the
// mise request grammar in the tables above rather than spelled out at each
// call site, so a new prefix reaches every classifier at once.
func hasAnyPrefix(s string, prefixes []string) bool {
	return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(s, p) })
}

// DeclaredVersion reduces a declared mise version request to the version line
// it constrains, looking through the wrappers mise resolves at install time.
// "prefix:20" constrains resolution to the 20 line exactly as "20" does; a
// subtraction moves the request off the line it names and onto a lower one, so
// "sub-1:20" constrains the 19 line, not the 20 line (see subtractSelector).
//
// ok is false when the request names no version at all: a channel or alias
// ("latest", "lts", "system"), a git ref or checkout ("ref:main",
// "path:/opt/go"), an empty token, or a subtraction Deputy cannot evaluate
// without resolving its base first ("sub-2:lts"). Such a request may resolve
// to any release, so its text rules nothing out; one that does carry a version
// can only resolve to that version or, when it is partial, to a release
// beneath it.
//
// This is the discriminator remediation needs before overwriting a
// declaration a stale plan no longer describes. "Starts with a digit" is not
// it: mise's Java versions are vendor-prefixed exact releases
// ("temurin-21.0.6+7"), and reading those as floating selectors lets an old
// plan replace a newer toolchain with an older one. Nor is "strip the wrapper
// and keep the base": that reads "sub-1:20" as governing the 20 line, so a
// plan built for 20.11.0 overwrites a declaration that installs 19.9.0, while
// the plan that does describe it is refused.
func DeclaredVersion(request string) (version string, ok bool) {
	s := strings.TrimSpace(request)
	for {
		base, sub, wrapped := trimSelectorWrapper(s)
		if !wrapped {
			break
		}
		s = strings.TrimSpace(base)
		if sub == "" {
			continue
		}
		derived, derivedOK := subtractSelector(s, sub)
		if !derivedOK {
			return "", false
		}
		s = derived
	}
	// A wrapper the loop could not strip is a request mise itself refuses, so
	// its text names no release to reason about.
	if hasAnyPrefix(s, selectorWrapperPrefixes) {
		return "", false
	}
	if _, floating := fuzzyChannels[strings.ToLower(s)]; floating {
		return "", false
	}
	if hasAnyPrefix(s, unversionedPrefixes) {
		return "", false
	}
	// No digit anywhere means no version number to pin the request down: an
	// alias such as "lts" or a codename mise resolves against the registry.
	if !strings.ContainsAny(s, "0123456789") {
		return "", false
	}
	return s, true
}

// SelectorMatches reports whether a version request selects a concrete
// release, which is the question behind "could this declaration still be
// resolving to the version the finding names".
//
// A partial request governs the line beneath it, matching a version it equals
// or whose dot-separated components it is a leading run of. Verified against
// mise 2026.7.3 by resolving real configs, since that is what a declaration
// does: `node = "20.1"` reports 20.1.0 under `mise ls --current` and locks as
// node@20.1.0 under `mise lock --dry-run`, `node = "20.11"` reports 20.11.1,
// `node = "20"` reports 20.20.2, and `node = "2"` resolves to nothing at all
// and stays missing.
//
// `mise ls-remote` is not this rule and must not be cited as it. It is a loose
// listing filter: `ls-remote node@20.1` prints all 25 releases from 20.1.0
// through 20.19.6, but a config declaring 20.1 installs 20.1.0. Reading the
// listing filter as the resolution rule makes the match leading-character and
// therefore too permissive, letting remediation rewrite a declaration that
// does not govern the reported version at all.
//
// A release prefix on either side is ignored, so "v20" still selects "20.11.0"
// and, for the Go toolchain, "go1.24" still selects "1.24.9"; which prefixes
// those are depends on the tool, so toolKey is the [tools] key the versions
// belong to (see [TrimVersionPrefix]).
func SelectorMatches(toolKey, request, version string) bool {
	request = TrimVersionPrefix(toolKey, request)
	version = TrimVersionPrefix(toolKey, version)
	if request == version {
		return true
	}
	return len(version) > len(request) &&
		strings.HasPrefix(version, request) &&
		version[len(request)] == '.'
}

// SameVersion reports whether two version tokens name the same release,
// ignoring a release prefix on either side. Which prefixes those are depends on
// the tool, so toolKey is the [tools] key whose versions are being compared
// (see [TrimVersionPrefix]).
//
// The two sides reach this comparison from different vocabularies. Deputy
// reports the Go runtime with the module convention it is published under
// ("v1.22.12"), while a mise config and its lockfile write the release as mise
// installs it ("1.22.12"). A byte-for-byte comparison makes those disagree, so
// remediation refuses to rewrite an array element the finding does describe
// and, worse, leaves the sibling lock entry in place: lock resolution then
// substitutes the version the fix just removed, and the next scan reports the
// vulnerability again against a config that no longer declares it.
//
// This is equality, not selection. "20" and "20.11.0" are different tokens
// here even though the first request resolves to the second; deciding whether
// a declaration governs a release is [SelectorMatches]'s job, and using it for
// equality would let a partial selector stand in for an exact version.
func SameVersion(toolKey, a, b string) bool {
	return TrimVersionPrefix(toolKey, a) == TrimVersionPrefix(toolKey, b)
}

// tagPrefixes are the release prefixes any tool's version token may carry
// without naming a different release: the "v" of a git tag or Go module version
// ("v1.22.12"), which Deputy reports the Go runtime under and which mise itself
// ignores when it compares a request to a release.
//
// A token spelling the same release in a different vocabulary has to compare
// equal, or the two sides of a fix disagree about what the config says: the
// rewriter reads a declaration the finding does describe as some other version
// and refuses to touch it, and the pruner reads a lock entry the fix made stale
// as another tool's business and leaves it to be served back.
var tagPrefixes = []string{"v", "V"}

// goToolchainPrefixes are release prefixes only the Go toolchain carries. mise
// accepts the Go project's own spelling in a declaration (`go = "go1.24"`) and
// go.dev publishes releases as "go1.24.9", while mise locks and installs the
// bare number, so for that one tool the two spell one release.
//
// No other tool gets this rule, because for everything else a version is an
// opaque release tag: a ubi tool can publish both "go1.3.0" and "1.3.0" as
// different artifacts, and calling them equal let a fix that asked for one
// report success against the other without writing anything.
var goToolchainPrefixes = []string{"go", "Go", "GO"}

// TrimVersionPrefix drops a release prefix from a version token, so "v1.24.3"
// and "1.24.3" are one release for any tool, and "go1.24.3" is that release too
// when toolKey names the Go toolchain. It is the one normalization behind
// [SameVersion] and [SelectorMatches], so equality and selection cannot read a
// spelling differently.
//
// A prefix is only dropped when a digit follows it, which keeps the rule from
// reaching a name it does not govern: a tool called "vault" or "golang" keeps
// its name, and only a token that goes on to spell a version number is
// normalized. That guard alone is not enough for "go", because a version is
// only a version number for tools whose releases are numbered; hence the tool.
func TrimVersionPrefix(toolKey, s string) string {
	s = strings.TrimSpace(s)
	prefixes := tagPrefixes
	if IsGoToolchain(toolKey) {
		prefixes = append(slices.Clone(tagPrefixes), goToolchainPrefixes...)
	}
	for _, prefix := range prefixes {
		rest, ok := strings.CutPrefix(s, prefix)
		if ok && rest != "" && rest[0] >= '0' && rest[0] <= '9' {
			return rest
		}
	}
	return s
}

// IsGoToolchain reports whether a [tools] key names the Go toolchain itself,
// the runtime whose releases are spelled "go1.24.9": mise declares it as `go`
// or `golang` with no backend, or through the core backend that serves it.
//
// The go backend is deliberately not it. `go:github.com/foo/bar` installs a Go
// module with `go install`, and its versions are module versions ("v1.2.3"), so
// a "go" prefix there would be part of a tag rather than the toolchain's
// spelling of a release.
func IsGoToolchain(toolKey string) bool {
	backend, name := SplitBackend(toolKey)
	if backend != "" && backend != "core" {
		return false
	}
	switch strings.ToLower(name) {
	case "go", "golang":
		return true
	}
	return false
}

// trimSelectorWrapper strips one leading mise selector wrapper from a version
// request, returning the request it wraps and, for a "sub-" wrapper, the
// subtrahend it carries: "prefix:20" yields base "20" with no subtrahend, and
// "sub-1:lts" yields base "lts" with subtrahend "1". sub is empty exactly when
// the wrapper does not subtract, so a caller can tell "prefix:20" from a
// malformed "sub-:20" without re-reading the prefix.
//
// ok is false when no wrapper is present, the wrapper has nothing to wrap, or
// a "sub-" wrapper carries no subtrahend. The request is then classified as
// written, and DeclaredVersion refuses one that still begins with a wrapper.
func trimSelectorWrapper(s string) (base, sub string, ok bool) {
	for _, prefix := range selectorWrapperPrefixes {
		if !strings.HasPrefix(s, prefix) {
			continue
		}
		rest := s[len(prefix):]
		if prefix == "sub-" {
			// "sub-<n>:<base>": the count belongs to the wrapper, not to the
			// request being wrapped.
			count, wrapped, found := strings.Cut(rest, ":")
			if !found || strings.TrimSpace(count) == "" {
				return "", "", false
			}
			sub, rest = strings.TrimSpace(count), wrapped
		}
		if rest == "" {
			return "", "", false
		}
		return rest, sub, true
	}
	return "", "", false
}

// subtractSelector applies a mise "sub-" subtrahend to the base request it
// wraps, returning the version line the wrapped request actually resolves
// under.
//
// mise subtracts component-wise from the base as written, keeping only as many
// components as the subtrahend has, so "sub-1:20.11" governs the 19 line and
// not a nonexistent 19.11. A subtrahend longer than the base is truncated to
// the base, leaving "sub-0.1:20" governing the same line as plain "20".
// Subtracting past zero floors there. Verified against mise 2026.7.3 by
// resolving real configs and reading `mise ls --current`:
//
//	sub-1:20        -> 19.9.0     sub-0.1:20.11   -> 20.10.0
//	sub-1:20.11     -> 19.9.0     sub-0.1:20.11.1 -> 20.10.0
//	sub-1:20.11.1   -> 19.9.0     sub-0.1:20      -> 20.20.2
//	sub-2:24        -> 22.23.2    sub-0.0.1:20    -> 20.20.2
//	sub-30:20       -> 0.12.18    sub-0.0.1:20.11 -> 20.11.1
//
// ok is false when either side is not a plain dotted numeric run. The base may
// be a channel ("sub-2:lts") or a vendor-prefixed release, and mise resolves
// those before subtracting, which cannot be done from the config text alone;
// such a request rules no release out, which is what the caller reports.
func subtractSelector(base, sub string) (derived string, ok bool) {
	baseParts, baseOK := dottedNumbers(base)
	if !baseOK {
		return "", false
	}
	subParts, subOK := dottedNumbers(sub)
	if !subOK {
		return "", false
	}
	parts := make([]string, min(len(subParts), len(baseParts)))
	for i := range parts {
		parts[i] = strconv.Itoa(max(baseParts[i]-subParts[i], 0))
	}
	return strings.Join(parts, "."), true
}

// maxVersionComponentDigits bounds a single version component so an absurdly
// long numeric run in a user-authored request cannot overflow the conversion.
// Real components are a few digits at most.
const maxVersionComponentDigits = 9

// dottedNumbers parses a plain dotted numeric run ("20.11") into its
// components. ok is false for anything else: an empty string, a vendor prefix
// or prerelease suffix, a sign, or a component too long to be a real one. A
// request that cannot be reduced to numbers exactly is reported as unreadable
// rather than reduced approximately, because an approximate reading is what
// lets remediation rewrite a declaration it does not describe.
func dottedNumbers(s string) (components []int, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	for part := range strings.SplitSeq(s, ".") {
		if part == "" || len(part) > maxVersionComponentDigits {
			return nil, false
		}
		for i := range len(part) {
			if part[i] < '0' || part[i] > '9' {
				return nil, false
			}
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}
		components = append(components, n)
	}
	return components, true
}
