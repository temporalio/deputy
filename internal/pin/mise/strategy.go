// Package mise implements the pin.Strategy for mise-en-place toolchains. It
// pins fuzzy tool version requests in mise.toml ("node = \"20\"", "latest",
// "lts", partial versions) to exact, reproducible versions ("node = \"20.11.0\"").
//
// Resolution uses Deputy's native resolvers for registry-backed mise backends.
// Callers may also provide an explicit mise executable path as a fallback for
// backends Deputy does not resolve natively. Discovery, classification, and
// rewriting are local and require no network or mise binary, so `deputy pin
// check` works as a CI gate even where mise is not installed.
package mise

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	scalibrfs "github.com/google/osv-scalibr/fs"

	"github.com/temporalio/deputy/internal/forge"
	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/pin"
)

// Ecosystem identifiers for the toolchain pin strategies.
const (
	// Ecosystem pins fuzzy tool versions in mise.toml-family configs.
	Ecosystem = "mise"
	// AsdfEcosystem pins fuzzy tool versions in asdf .tool-versions files.
	AsdfEcosystem = "asdf"
)

// arraySentinel separates the versions of an array-valued tool in a Ref. mise
// versions never contain commas, so it reliably flags array entries (which the
// strategy skips rather than risk an incorrect multi-version rewrite).
const arraySentinel = ","

// Strategy implements pin.Strategy for mise/asdf toolchains. The discovery,
// resolution, and classification logic is identical across both; only the
// matched config format, the file rewriter, and the ecosystem name differ, so a
// single parameterized type serves both ecosystems.
type Strategy struct {
	ecosystem string
	format    mise.Format
	rewrite   func(root *os.Root, relPath string, updates []pin.Update) error
	resolver  Resolver
}

// NewStrategy returns a mise.toml pin strategy backed by Deputy's native
// resolver.
func NewStrategy() *Strategy { return miseStrategy(newNativeResolver()) }

// NewStrategyWithHostFallback returns a mise.toml strategy that uses native
// resolution for supported backends and the exact mise executable path provided
// as a fallback for non-native backends.
func NewStrategyWithHostFallback(misePath string) (*Strategy, error) {
	resolver, err := newResolverWithHostFallback(misePath)
	if err != nil {
		return nil, err
	}
	return miseStrategy(resolver), nil
}

// NewStrategyWithResolver returns a mise.toml strategy with a custom resolver (for tests).
func NewStrategyWithResolver(r Resolver) *Strategy { return miseStrategy(r) }

// NewAsdfStrategy returns a .tool-versions pin strategy backed by Deputy's
// native resolver.
func NewAsdfStrategy() *Strategy { return asdfStrategy(newNativeResolver()) }

// NewAsdfStrategyWithHostFallback returns a .tool-versions strategy that uses
// native resolution for supported backends and the exact mise executable path
// provided as a fallback for non-native backends.
func NewAsdfStrategyWithHostFallback(misePath string) (*Strategy, error) {
	resolver, err := newResolverWithHostFallback(misePath)
	if err != nil {
		return nil, err
	}
	return asdfStrategy(resolver), nil
}

// NewAsdfStrategyWithResolver returns a .tool-versions strategy with a custom resolver (for tests).
func NewAsdfStrategyWithResolver(r Resolver) *Strategy { return asdfStrategy(r) }

func miseStrategy(r Resolver) *Strategy {
	return &Strategy{ecosystem: Ecosystem, format: mise.FormatTOML, rewrite: rewriteMiseVersions, resolver: r}
}

func asdfStrategy(r Resolver) *Strategy {
	return &Strategy{ecosystem: AsdfEcosystem, format: mise.FormatToolVersions, rewrite: rewriteToolVersions, resolver: r}
}

// Ecosystem implements pin.Strategy.
func (s *Strategy) Ecosystem() string { return s.ecosystem }

// Close releases resources held by the strategy's resolver, such as a pooled
// deps.dev API connection. It is safe to call when the resolver holds no
// releasable resources (e.g. a test double or the host-binary resolver).
func (s *Strategy) Close() error {
	if c, ok := s.resolver.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// IsPinned implements pin.Strategy: a tool is pinned when its version is a
// concrete resolver output.
func (s *Strategy) IsPinned(ref pin.Ref) bool {
	if mise.IsExactVersion(ref.Version) {
		return true
	}
	backend, name := mise.SplitBackend(ref.Name)
	if _, _, ok := githubReleaseRepo(backend, name); ok {
		return mise.IsConcreteVersion(ref.Version)
	}
	return false
}

// ShouldSkip implements pin.Strategy. It skips entries that cannot or should not
// be pinned to a single exact version.
func (s *Strategy) ShouldSkip(ref pin.Ref) (bool, string) {
	v := strings.TrimSpace(ref.Version)
	switch {
	case v == "":
		return true, "no version specified"
	case strings.Contains(v, arraySentinel):
		return true, "multiple versions (pin manually)"
	case strings.EqualFold(v, "system"):
		return true, "system version"
	case strings.HasPrefix(v, "file:"), strings.HasPrefix(v, "ref:"), strings.HasPrefix(v, "path:"):
		return true, "non-resolvable reference"
	}
	if forge, ok := nonGitHubForge(ref); ok {
		return true, fmt.Sprintf("%s-hosted tool: native resolution supports GitHub releases only "+
			"(pin manually or use --allowed-host-bins)", forge)
	}
	return false, ""
}

// nonGitHubForge reports whether a ubi:/github: tool targets a forge other than
// GitHub — via a provider/forge tool option (e.g. "[provider=gitlab]") or a
// host embedded in the spec (e.g. "ubi:gitlab.com/owner/repo"). Such tools are
// resolved by mise against that forge's release API, which Deputy's native
// resolver does not yet implement, so it must not silently resolve them against
// GitHub. It returns the forge name (lowercased) for the skip message.
//
// TODO(deputy): add first-class non-GitHub forge resolution for ubi:/github:
// tools, following the existing GitHub forge model in internal/forge: start
// with public GitLab (release + tag listing, no auth), then authenticated
// GitLab (token via the auth provider), then Gitea/Forgejo/Codeberg. Until
// then these are reported as skipped rather than mis-resolved. See
// [internal/forge] and [internal/releases] for the client shape to mirror.
func nonGitHubForge(ref pin.Ref) (string, bool) {
	backend, name := mise.SplitBackend(ref.Name)
	if backend != "ubi" && backend != "github" {
		return "", false
	}
	// Provider/forge tool option naming a non-GitHub host.
	for _, key := range []string{"provider", "forge", "host", "api_url"} {
		if val := strings.ToLower(strings.TrimSpace(ref.Options[key])); val != "" {
			if forge, ok := nonGitHubForgeName(val); ok {
				return forge, true
			}
		}
	}
	// A host embedded in the spec name (GitHub specs are bare owner/repo, so a
	// dot in the first path segment indicates an explicit non-GitHub host).
	if owner, _, _ := forge.SplitOwnerRepoRest(name); strings.Contains(owner, ".") {
		if f, ok := nonGitHubForgeName(owner); ok {
			return f, true
		}
		return "non-github", true
	}
	return "", false
}

// nonGitHubForgeName maps a provider/forge/host value to a forge label, or
// reports false when it denotes GitHub (the natively supported forge).
func nonGitHubForgeName(val string) (string, bool) {
	switch {
	case val == "", val == "github", strings.Contains(val, "github.com"):
		return "", false
	case strings.Contains(val, "gitlab"):
		return "gitlab", true
	case strings.Contains(val, "gitea"):
		return "gitea", true
	case strings.Contains(val, "forgejo"), strings.Contains(val, "codeberg"):
		return "forgejo", true
	default:
		return val, true
	}
}

// stringOptions narrows a parsed mise options map to its string-valued entries
// (provider, exe, matching, …), which are the ones pin resolution cares about.
func stringOptions(opts map[string]any) map[string]string {
	if len(opts) == 0 {
		return nil
	}
	out := make(map[string]string, len(opts))
	for k, v := range opts {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Discover implements pin.Strategy. It walks the filesystem for committed
// configs of this strategy's format and emits a Ref per declared tool.
// Developer-local mise.toml overrides (mise.local.toml) are skipped since they
// are not shared.
func (s *Strategy) Discover(ctx context.Context, fsys scalibrfs.FS) ([]pin.Ref, error) {
	var refs []pin.Ref
	seen := map[string]bool{}
	// One scope for the whole walk: it enumerates the filesystem's configs once
	// and memoizes the claimant counts per lockfile, so a directory of conf.d
	// drop-ins is listed and parsed once rather than once per drop-in.
	scope := mise.NewLockScope(fsys)

	err := fs.WalkDir(fsys, ".", func(relPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if pin.ShouldSkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if pin.IsSymlink(d) {
			return nil
		}
		format, ok := mise.IsConfigPath(relPath)
		if !ok || format != s.format {
			return nil
		}
		if s.format == mise.FormatTOML && mise.IsLocalConfig(relPath) {
			return nil
		}
		content, err := fs.ReadFile(fsys, relPath)
		if err != nil {
			slog.DebugContext(ctx, "toolchain pin: skipping unreadable config", "path", relPath, "error", err)
			return nil
		}
		cfg, err := mise.Parse(relPath, content)
		if err != nil {
			slog.DebugContext(ctx, "toolchain pin: skipping unparseable config", "path", relPath, "error", err)
			return nil
		}
		lock, err := mise.LoadSiblingLock(fsys, relPath)
		if err != nil {
			slog.DebugContext(ctx, "toolchain pin: skipping unusable lockfile", "path", mise.LockfilePath(relPath), "error", err)
		}
		// Which names are claimed across every config sharing this lockfile,
		// so a locked version is not lent to a declaration that may not own
		// the entry it came from. The scope is the lockfile's, not this
		// file's: a mise directory's conf.d drop-ins all write to one
		// mise.lock. With ownership unresolved nothing is provably this
		// config's, so the lockfile is set aside and the tools resolve
		// upstream instead of pinning to an entry that might be another
		// declaration's.
		var claims map[string]int
		if lock != nil {
			claims, err = scope.Claims(relPath)
			if err != nil {
				slog.DebugContext(ctx, "toolchain pin: lock ownership unresolved, ignoring lockfile", "path", relPath, "error", err)
				lock = nil
			}
		}
		for _, tool := range cfg.Tools {
			version := versionForRef(tool.Versions)
			if version == "" {
				continue
			}
			ref := pin.Ref{
				Ecosystem: s.ecosystem,
				Name:      tool.Key,
				Version:   version,
				FilePath:  relPath,
				Raw:       tool.Key + " " + version,
				Options:   stringOptions(tool.Options),
			}
			ref.LockedVersion = lockedVersionForRef(lock, tool, version, claims)
			key := pin.DedupeKey(ref)
			if !seen[key] {
				seen[key] = true
				refs = append(refs, ref)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanning %s configs: %w", s.ecosystem, err)
	}
	return refs, nil
}

// versionForRef collapses a tool's requested versions into a single Ref version
// string, joining multiple versions with the array sentinel so they are skipped.
func versionForRef(versions []string) string {
	switch len(versions) {
	case 0:
		return ""
	case 1:
		return versions[0]
	default:
		return strings.Join(versions, arraySentinel)
	}
}

// lockedVersionForRef returns a compatible exact version from a sibling
// mise.lock entry. It rejects ambiguous or stale-looking fuzzy matches so pin
// can preserve an existing lock without blindly trusting unrelated lock data.
//
// claims carries how many declarations across the configs sharing the lockfile
// could own each name, and the gates it feeds are the ones inventory applies
// in [mise.Lockfile.Lookup]. Without them a legacy [[tools.foo]] entry is
// accepted for a declaration of "npm:foo" and for one of "ubi:foo" alike, and
// pin writes one backend's locked version into the other's declaration.
func lockedVersionForRef(lock *mise.Lockfile, tool mise.ToolSpec, request string, claims map[string]int) string {
	if lock == nil || strings.Contains(request, arraySentinel) {
		return ""
	}
	names := mise.LockCandidateNames(tool)
	for _, name := range names {
		if !mise.MayMatchLockName(tool, name, claims) {
			continue
		}
		if lt := lock.Locked(name, request); lt != nil && mise.IsConcreteVersion(lt.Version) {
			return lt.Version
		}
	}
	for _, name := range names {
		if !mise.MayBorrowSoleLockEntry(name, claims) {
			continue
		}
		if lt := lock.Sole(name); lt != nil && lockedVersionSatisfiesRequest(tool.Key, lt.Version, request) {
			return lt.Version
		}
	}
	return ""
}

// lockedVersionSatisfiesRequest reports whether a sole lockfile entry is
// compatible with a declared selector without consulting upstream metadata.
func lockedVersionSatisfiesRequest(toolKey, locked, request string) bool {
	if !mise.IsConcreteVersion(locked) {
		return false
	}
	request = strings.TrimSpace(request)
	if request == "" {
		return false
	}
	if prefix, ok := strings.CutPrefix(request, "prefix:"); ok {
		return versionHasPrefix(toolKey, locked, prefix)
	}
	if strings.HasPrefix(request, "sub-") {
		return true
	}
	switch strings.ToLower(request) {
	case "latest", "lts", "stable", "current":
		return true
	case "system":
		return false
	}
	if strings.HasPrefix(request, "file:") || strings.HasPrefix(request, "ref:") || strings.HasPrefix(request, "path:") {
		return false
	}
	if strings.ContainsAny(request, "^~*<>= ") || strings.Contains(request, "..") {
		return false
	}
	return versionHasPrefix(toolKey, locked, request)
}

// versionHasPrefix reports whether a fuzzy request selects a concrete version,
// deferring to [mise.SelectorMatches] so this answers the question the same way
// the remediation staleness gate and the release filter do. The rule was
// spelled out here as well, and a second copy of a rule is a second answer
// waiting to disagree with the first; they happened to agree, and now they
// cannot do otherwise.
//
// The Go toolchain's "go" prefix, which mise selectors carry and mise's own
// locked versions do not, was stripped here too. [mise.SelectorMatches] now
// normalizes it, so discovery and remediation cannot disagree about whether
// "go1.24" selects 1.24.9: they did, and a fix Deputy planned from a discovered
// version came back as "could not rewrite".
func versionHasPrefix(toolKey, version, prefix string) bool {
	return mise.SelectorMatches(toolKey, prefix, version)
}

// Resolve implements pin.Strategy. It resolves a fuzzy version to an exact one.
// The original request is returned as the version tag for display context.
func (s *Strategy) Resolve(ctx context.Context, ref pin.Ref) (pinnedValue, versionTag string, err error) {
	if ref.LockedVersion != "" {
		if !mise.IsConcreteVersion(ref.LockedVersion) {
			return "", "", fmt.Errorf("locked version %q for %s is not concrete", ref.LockedVersion, ref.Name)
		}
		return ref.LockedVersion, ref.Version, nil
	}
	exact, err := s.resolver.Latest(ctx, ref.Name, ref.Version)
	if err != nil {
		return "", "", err
	}
	// Trust the resolver's authoritative output: it may be a partial-but-final
	// version (e.g. protobuf "33.1"), which IsExactVersion would reject but is
	// still the most specific version the tool publishes.
	if !mise.IsConcreteVersion(exact) {
		return "", "", fmt.Errorf("resolved version %q for %s is not concrete", exact, ref.Name)
	}
	return exact, ref.Version, nil
}

// Verify implements pin.Strategy. mise verifies tool provenance (cosign, SLSA,
// GitHub attestations) at install time; there is no separate pin-time
// provenance check, so this returns nil.
func (s *Strategy) Verify(_ context.Context, _ pin.Ref) (*pin.Verification, error) {
	return nil, nil
}

// ResolveUpdate implements pin.Strategy. For an already-pinned concrete version
// it re-resolves to the newest release within the same major version channel.
func (s *Strategy) ResolveUpdate(ctx context.Context, ref pin.Ref) (pinnedValue, newVersionTag, currentVersionTag string, err error) {
	channel := majorChannel(ref.Version)
	exact, err := s.resolver.Latest(ctx, ref.Name, channel)
	if err != nil {
		return "", "", "", err
	}
	if exact == ref.Version {
		return ref.Version, ref.Version, ref.Version, nil // no change
	}
	if !mise.IsConcreteVersion(exact) {
		return "", "", "", fmt.Errorf("resolved update %q for %s is not concrete", exact, ref.Name)
	}
	return exact, exact, ref.Version, nil
}

// majorChannel returns the major-version prefix of an exact version so updates
// stay within the same major (e.g. "20.11.0" -> "20"). A leading "v" is kept.
func majorChannel(version string) string {
	major, _, _ := strings.Cut(strings.TrimSpace(version), ".")
	return major
}

// Rewrite implements pin.Strategy, dispatching to this strategy's format writer.
func (s *Strategy) Rewrite(root *os.Root, relPath string, updates []pin.Update) error {
	return s.rewrite(root, relPath, updates)
}
