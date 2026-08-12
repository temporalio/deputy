package remediation

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/pin"
	"github.com/temporalio/deputy/internal/pin/githubactions"
	pinmise "github.com/temporalio/deputy/internal/pin/mise"
)

// IsDeputyInternalCommand checks if a command is a deputy-internal command
// that should be executed by Deputy directly rather than as a shell command.
func IsDeputyInternalCommand(cmd string) bool {
	return strings.HasPrefix(cmd, "deputy:")
}

// fileEdits orders the file edits [ApplyDeputyCommand] performs within a
// process. Every one of them reads a file, computes a new version of it, and
// publishes that, so two overlapping edits read the same bytes, compute two
// independent results, and write them one over the other. The loser's change is
// silently gone while both report success: two fixes for tools declared in one
// mise.toml, or for tools whose configs share a mise.lock, leave one tool
// unedited or one stale lock entry alive, and the next scan reports the fix as
// ineffective at the version it just removed.
//
// The unit is the working tree, not the file. Within a tree the files alias: a
// mise.lock reached through a symlink belongs to every directory that links to
// it, so keying on the config would not order two configs sharing a lockfile; a
// config reached through a symlink is one file under two names, so keying on the
// manifest path would not order those either; and taking a lock per resource
// invites a deadlock over their order. An edit is a handful of operations on
// files of a few kilobytes and every caller applies its plan's steps one at a
// time, so finer granularity within a tree would buy nothing.
//
// Across trees there is nothing to order, and one lock for the process is a
// bottleneck a shared deployment feels: the server executes a plan step by
// step through this function, so a slow read, write, or fsync in one request
// would stall every other tenant's remediation behind it.
//
// The guard is process-local. Two `deputy fix` runs over one working tree still
// race, on these files and on the working tree itself, and ordering those would
// take a filesystem lock that Deputy does not take.
var fileEdits = newEditGuards()

// editGuards lets edits to unrelated working trees run at once while any two
// that could touch one file still take turns.
//
// Two trees are unrelated only when neither contains the other. A nested work
// directory shares files with the tree above it, so a plan applied to a
// monorepo root and a plan applied to one of its subdirectories are ordered
// against each other exactly as two plans over one tree are; treating them as
// independent would trade the bottleneck for the lost update this guard exists
// to prevent. Overlap is decided by path containment rather than by a lock per
// tree, so no holder ever waits on a second guard and there is no ordering to
// deadlock over.
//
// Entries live only while a tree is held or waited on, so the map is bounded by
// the number of edits in flight rather than by the number of trees a
// long-running daemon has ever seen.
type editGuards struct {
	mu   sync.Mutex
	cond *sync.Cond
	held map[string]struct{}
}

// newEditGuards returns an empty set of guards.
func newEditGuards() *editGuards {
	g := &editGuards{held: make(map[string]struct{})}
	g.cond = sync.NewCond(&g.mu)
	return g
}

// guard blocks until no edit is in flight against a working tree overlapping
// dir, then claims dir and returns the release to call when the edit is done.
func (g *editGuards) guard(dir string) (release func()) {
	key := treeIdentity(dir)

	g.mu.Lock()
	for g.overlapsHeldLocked(key) {
		g.cond.Wait()
	}
	g.held[key] = struct{}{}
	g.mu.Unlock()

	return func() {
		g.mu.Lock()
		delete(g.held, key)
		g.mu.Unlock()
		// Any waiter may now be free, and which ones depends on the key that
		// was released, so they all get to re-check rather than one being
		// picked that may still be blocked.
		g.cond.Broadcast()
	}
}

// overlapsHeldLocked reports whether an edit is in flight against a tree that
// shares files with key. The caller holds g.mu.
func (g *editGuards) overlapsHeldLocked(key string) bool {
	for held := range g.held {
		if treesOverlap(held, key) {
			return true
		}
	}
	return false
}

// treeIdentity names the working tree a directory belongs to, so that two edits
// reaching one tree by different spellings take one turn. The path is made
// absolute and its symlinks resolved, since a relative path, an absolute one,
// and a link into the same directory are the same tree and a fix applied
// through one of them is visible through the others.
//
// A directory whose identity cannot be established (it does not exist, or a
// parent cannot be read) is named by the empty string, which [treesOverlap]
// treats as overlapping everything: an edit Deputy cannot place is ordered
// against all of them rather than against none. Such an edit is about to fail
// on the same missing directory anyway, so the cost is nothing and the
// alternative is two spellings of one tree running at once.
func treeIdentity(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return ""
	}
	return resolved
}

// treesOverlap reports whether two working trees can touch the same file, which
// is true when they are the same tree or one contains the other. An unknown
// identity (the empty string) overlaps everything, so nothing runs beside an
// edit whose tree could not be placed.
func treesOverlap(a, b string) bool {
	if a == "" || b == "" {
		return true
	}
	if a == b {
		return true
	}
	return contains(a, b) || contains(b, a)
}

// contains reports whether sub is dir or sits beneath it. The answer comes from
// [filepath.Rel] rather than a string prefix, so a sibling whose name merely
// starts with the directory's ("/w/repo" and "/w/repo-fork") is not read as
// nested; only a path that climbs out of dir is outside it, and a directory may
// legitimately be named "..data", as Kubernetes secret mounts are.
//
// A pair of paths that cannot be related at all (separate volumes on Windows) is
// reported as contained, keeping the answer conservative: two trees are only
// allowed to run at once when they are known not to overlap.
func contains(dir, sub string) bool {
	rel, err := filepath.Rel(dir, sub)
	if err != nil {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// ApplyDeputyCommand executes a deputy-internal command.
// Returns an error if the command is not recognized or fails.
//
// The edit is serialized by [fileEdits] against every other one in the process
// that could touch the same files, so a command reads the file its predecessor
// wrote rather than the bytes they both started from. Edits to unrelated
// working trees proceed at once.
func ApplyDeputyCommand(repoDir, cmd string) error {
	parts, err := ParseCommandArgs(cmd)
	if err != nil {
		return fmt.Errorf("invalid command: %w", err)
	}

	defer fileEdits.guard(repoDir)()

	switch parts[0] {
	case "deputy:action:update":
		// Format: deputy:action:update <file> <owner/repo> <new-version>
		if len(parts) < 4 {
			return fmt.Errorf("invalid action update command: expected 4 parts, got %d", len(parts))
		}
		file, err := safeJoinPath(repoDir, parts[1])
		if err != nil {
			return fmt.Errorf("invalid file path: %w", err)
		}
		actionRef := parts[2]
		newVersion := parts[3]
		return applyActionUpdate(file, actionRef, newVersion)

	case "deputy:action:pin":
		// Format: deputy:action:pin <file> <owner/repo[/subpath]> <sha> <tag>
		if len(parts) < 5 {
			return fmt.Errorf("invalid action pin command: expected 5 parts, got %d", len(parts))
		}
		file, err := safeJoinPath(repoDir, parts[1])
		if err != nil {
			return fmt.Errorf("invalid file path: %w", err)
		}
		actionRef := parts[2]
		sha := parts[3]
		tag := parts[4]
		return applyActionPin(repoDir, file, actionRef, sha, tag)

	case "deputy:mise:update":
		// Format: deputy:mise:update <file> <tool> <new-version> [<current-version>...]
		// The current versions target the vulnerable elements when the tool
		// declares multiple versions in an array.
		if len(parts) < 4 {
			return fmt.Errorf("invalid mise update command: expected at least 4 parts, got %d", len(parts))
		}
		// Validate containment, then keep working with the detected path
		// rather than safeJoinPath's symlink-resolved target: the manifest's
		// own location is what determines its sibling lockfile.
		if _, err := safeJoinPath(repoDir, parts[1]); err != nil {
			return fmt.Errorf("invalid file path: %w", err)
		}
		configRel, err := repoRelPath(repoDir, parts[1])
		if err != nil {
			return fmt.Errorf("invalid file path: %w", err)
		}
		tool := parts[2]
		newVersion := parts[3]
		currentVersions := parts[4:]
		return applyMiseUpdate(repoDir, configRel, tool, currentVersions, newVersion)

	case "deputy:dockerfile:update":
		// Format: deputy:dockerfile:update <file> <image> <new-version>
		if len(parts) < 4 {
			return fmt.Errorf("invalid dockerfile update command: expected 4 parts, got %d", len(parts))
		}
		file, err := safeJoinPath(repoDir, parts[1])
		if err != nil {
			return fmt.Errorf("invalid file path: %w", err)
		}
		image := parts[2]
		newVersion := parts[3]
		return applyDockerfileUpdate(file, image, newVersion)

	default:
		return fmt.Errorf("unknown deputy command: %s", parts[0])
	}
}

// safeJoinPath joins a base directory with a relative path, ensuring the result
// stays within the base directory. This prevents path traversal attacks.
//
// Note: This function uses filepath.EvalSymlinks to resolve symlinks and prevent
// symlink-based escapes. This adds a filesystem stat call but is necessary for
// security when the base directory exists.
func safeJoinPath(baseDir, relPath string) (string, error) {
	// Reject obviously malicious paths early
	if strings.Contains(relPath, "\x00") {
		return "", fmt.Errorf("path contains null byte")
	}

	// Clean the base path
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("invalid base directory: %w", err)
	}

	// Resolve symlinks in base directory if it exists
	if realBase, err := filepath.EvalSymlinks(absBase); err == nil {
		absBase = realBase
	}

	// Join and clean the result (lexical only, no symlink resolution yet)
	joined := filepath.Join(absBase, relPath)

	// Check lexically first - catch obvious traversal without filesystem access
	rel, err := filepath.Rel(absBase, joined)
	if err != nil || strings.HasPrefix(rel, "..") || rel == ".." {
		return "", fmt.Errorf("path traversal detected: %s escapes base directory", relPath)
	}

	// Now resolve symlinks in the full path to catch symlink-based escapes
	// We need to handle the case where the file doesn't exist yet
	realJoined := joined
	if resolved, err := filepath.EvalSymlinks(joined); err == nil {
		realJoined = resolved
	} else if !os.IsNotExist(err) {
		// If error is not "file doesn't exist", it's a real problem
		return "", fmt.Errorf("cannot resolve path: %w", err)
	} else {
		// File doesn't exist - check parent directory for symlink escapes
		parent := filepath.Dir(joined)
		if realParent, err := filepath.EvalSymlinks(parent); err == nil {
			realJoined = filepath.Join(realParent, filepath.Base(joined))
		}
	}

	// Final containment check after symlink resolution
	finalRel, err := filepath.Rel(absBase, realJoined)
	if err != nil || strings.HasPrefix(finalRel, "..") || finalRel == ".." {
		return "", fmt.Errorf("path escapes base directory after symlink resolution")
	}

	return realJoined, nil
}

// repoRelPath returns declared as a slash-separated path relative to repoDir,
// joined and cleaned the same lexical way safeJoinPath joins it but without
// resolving symlinks, so the file keeps the identity the scan gave it. That
// matters wherever a sibling file is derived from the manifest's location: an
// in-repository symlink (`mise.toml -> configs/shared.toml`) has a different
// sibling lockfile than its target, and following it would prune the wrong
// one. Containment is still enforced here, and again by the os.Root the caller
// opens.
func repoRelPath(repoDir, declared string) (string, error) {
	if strings.Contains(declared, "\x00") {
		return "", fmt.Errorf("path contains null byte")
	}
	base, err := filepath.Abs(repoDir)
	if err != nil {
		return "", fmt.Errorf("invalid base directory: %w", err)
	}
	rel, err := filepath.Rel(base, filepath.Join(base, declared))
	if err != nil {
		return "", fmt.Errorf("computing relative path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal detected: %s escapes base directory", declared)
	}
	return filepath.ToSlash(rel), nil
}

// applyActionUpdate updates a GitHub Action reference in a workflow file.
// It handles multiple formats idiomatically:
//
//   - uses: owner/repo@v1.2.3                    -> updates to @newVersion
//   - uses: owner/repo@abc123 # v1.2.3           -> updates comment to # newVersion (preserves SHA)
//   - uses: owner/repo@abc123                    -> updates to @newVersion (converts SHA to tag)
//
// The function preserves the user's style (quotes, spacing) and handles the
// idiomatic SHA-with-comment pattern used by security-conscious workflows.
// When a SHA is pinned with a version comment, we only update the comment
// because we cannot resolve the new SHA without GitHub API access. This
// signals to the user that they need to update the SHA manually.
func applyActionUpdate(filePath, actionRef, newVersion string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", filePath, err)
	}

	escapedRef := regexp.QuoteMeta(actionRef)
	contentStr := string(content)
	modified := false

	// First, handle SHA-pinned actions with version comments:
	//   uses: owner/repo@abc123def456... # v1.2.3
	// We preserve the SHA and update only the comment. The user will need to
	// update the SHA manually (or we could add GitHub API integration later).
	shaWithCommentPattern := fmt.Sprintf(
		`(uses:\s*["']?)(%s)@([0-9a-fA-F]{40})(["']?\s*#\s*)v?([^\s\n]+)`,
		escapedRef,
	)
	shaWithCommentRe, err := regexp.Compile(shaWithCommentPattern)
	if err != nil {
		return fmt.Errorf("compiling SHA+comment regex: %w", err)
	}

	if shaWithCommentRe.MatchString(contentStr) {
		// Preserve SHA, update comment to show the new version
		// Format: uses: owner/repo@<sha> # <newVersion>
		replacement := fmt.Sprintf("${1}${2}@${3}${4}%s", newVersion)
		contentStr = shaWithCommentRe.ReplaceAllString(contentStr, replacement)
		modified = true
	}

	// Then handle standard patterns (tag or bare SHA without comment):
	//   uses: owner/repo@v1.2.3
	//   uses: owner/repo@abc123def (no comment)
	if !modified {
		pattern := fmt.Sprintf(`(uses:\s*["']?)(%s)@([^"'\s#]+)(["']?)`, escapedRef)
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("compiling regex: %w", err)
		}

		replacement := fmt.Sprintf("${1}${2}@%s${4}", newVersion)
		newContent := re.ReplaceAllString(contentStr, replacement)
		if newContent != contentStr {
			contentStr = newContent
			modified = true
		}
	}

	if !modified {
		return fmt.Errorf("no matches found for action %s in %s", actionRef, filePath)
	}

	// Write back
	if err := os.WriteFile(filePath, []byte(contentStr), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", filePath, err)
	}

	return nil
}

// applyDockerfileUpdate updates a FROM instruction in a Dockerfile.
// It handles multiple formats idiomatically:
//
//   - FROM image:tag                      -> updates tag to newVersion
//   - FROM image:tag@sha256:...           -> updates tag, preserves digest (user updates digest manually)
//   - FROM image@sha256:... # tag         -> updates comment, preserves digest
//   - FROM image@sha256:...               -> converts to tag (FROM image:newVersion)
//   - FROM image                          -> adds tag (FROM image:newVersion)
//
// The function preserves the user's style (--platform, AS alias, spacing) and handles
// the security-conscious digest-pinned patterns. When a digest is present, we update
// the human-readable tag/comment but preserve the digest since we cannot resolve the
// new digest without registry API access.
func applyDockerfileUpdate(filePath, image, newVersion string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", filePath, err)
	}

	escapedImage := regexp.QuoteMeta(image)
	lines := strings.Split(string(content), "\n")
	modified := false

	// Pattern 1: FROM image:tag@sha256:digest (best practice - tag+digest)
	// Update the tag portion, preserve the digest
	tagDigestPattern := fmt.Sprintf(
		`(?i)^(\s*FROM\s+(?:--platform=[^\s]+\s+)?)(%s):([^\s@]+)(@sha256:[a-fA-F0-9]+)(\s+AS\s+\S+)?(\s*)$`,
		escapedImage,
	)
	tagDigestRe := regexp.MustCompile(tagDigestPattern)

	// Pattern 2: FROM image@sha256:digest # comment (digest with version comment)
	// Update the comment, preserve the digest
	digestCommentPattern := fmt.Sprintf(
		`(?i)^(\s*FROM\s+(?:--platform=[^\s]+\s+)?)(%s)(@sha256:[a-fA-F0-9]+)(\s+AS\s+\S+)?(\s*#\s*)([^\n]*)$`,
		escapedImage,
	)
	digestCommentRe := regexp.MustCompile(digestCommentPattern)

	// Pattern 3: FROM image@sha256:digest (digest only, no tag or comment)
	// Convert to tag-based reference
	digestOnlyPattern := fmt.Sprintf(
		`(?i)^(\s*FROM\s+(?:--platform=[^\s]+\s+)?)(%s)(@sha256:[a-fA-F0-9]+)(\s+AS\s+\S+)?(\s*)$`,
		escapedImage,
	)
	digestOnlyRe := regexp.MustCompile(digestOnlyPattern)

	// Pattern 4: FROM image:tag or FROM image (standard patterns)
	// Update or add tag
	standardPattern := fmt.Sprintf(
		`(?i)^(\s*FROM\s+(?:--platform=[^\s]+\s+)?)(%s)(?::([^\s@]+))?(\s+AS\s+\S+)?(\s*)$`,
		escapedImage,
	)
	standardRe := regexp.MustCompile(standardPattern)

	for i, line := range lines {
		var newLine string
		var matched bool

		// Try patterns in order of specificity
		switch {
		case tagDigestRe.MatchString(line):
			// FROM image:tag@sha256:digest -> FROM image:newVersion@sha256:digest
			newLine = tagDigestRe.ReplaceAllString(line, fmt.Sprintf("${1}${2}:%s${4}${5}${6}", newVersion))
			matched = true

		case digestCommentRe.MatchString(line):
			// FROM image@sha256:digest # comment -> FROM image@sha256:digest # newVersion
			newLine = digestCommentRe.ReplaceAllString(line, fmt.Sprintf("${1}${2}${3}${4}${5}%s", newVersion))
			matched = true

		case digestOnlyRe.MatchString(line):
			// FROM image@sha256:digest -> FROM image:newVersion (removes digest)
			newLine = digestOnlyRe.ReplaceAllString(line, fmt.Sprintf("${1}${2}:%s${4}${5}", newVersion))
			matched = true

		case standardRe.MatchString(line):
			// FROM image:tag or FROM image -> FROM image:newVersion
			newLine = standardRe.ReplaceAllString(line, fmt.Sprintf("${1}${2}:%s${4}${5}", newVersion))
			matched = true
		}

		if matched && newLine != line {
			lines[i] = newLine
			modified = true
		}
	}

	if !modified {
		return fmt.Errorf("no FROM %s found in %s", image, filePath)
	}

	// Write back, preserving original line endings
	output := strings.Join(lines, "\n")

	if err := os.WriteFile(filePath, []byte(output), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", filePath, err)
	}

	return nil
}

// applyMiseUpdate bumps a tool version in a mise.toml-family config by editing
// the file directly, so applying the fix never shells out to mise: `mise use`
// refuses untrusted configs (fatal in fresh checkouts and CI), picks its own
// write target instead of the detected manifest, and collapses multi-version
// arrays to a scalar. Delegates to pinmise.RewriteToolVersion for a single
// source of truth on format-preserving mise config rewrites, then prunes any
// stale sibling mise.lock entries so lock resolution cannot keep substituting
// the vulnerable version the fix just removed.
//
// configRel is the detected manifest as a slash-separated path relative to
// repoDir, kept unresolved on purpose: it is the path inventory read the
// config and its lockfile from, so deriving the lockfile from it prunes the
// lock that is actually in effect even when the manifest is an in-repository
// symlink. Containment comes from the os.Root, which refuses to traverse a
// link that leaves the repository. currentVersions may be empty when unknown
// (array declarations then fail closed rather than guess).
func applyMiseUpdate(repoDir, configRel, tool string, currentVersions []string, newVersion string) error {
	root, err := os.OpenRoot(repoDir)
	if err != nil {
		return fmt.Errorf("opening repo root: %w", err)
	}
	defer root.Close()

	if err := pinmise.RewriteToolVersion(root, configRel, tool, currentVersions, newVersion); err != nil {
		return fmt.Errorf("updating mise config: %w", err)
	}
	if err := pruneStaleMiseLock(root, configRel, tool, currentVersions, newVersion); err != nil {
		return fmt.Errorf("updating mise lockfile: %w", err)
	}
	return nil
}

// miseLockKeys returns the mise.lock table keys to prune for the tool that was
// just edited: the configured key and, when a backend prefix makes them differ,
// its backend-stripped short name, each of them only when no other declaration
// could own it. A config can declare both a backend-qualified tool and its
// short name as separate tools (`"npm:node"` and `node`), and several configs
// write into one lockfile, so pruning a contested name would discard integrity
// metadata for a declaration that was never edited.
//
// Ownership is the claimant count from [mise.LockClaims], nothing else, and the
// exact key is subject to it like any other name. Two configs sharing a
// lockfile can spell the same key at the same version, in which case the single
// entry is the one the config nobody edited still installs from. Withholding it
// costs the fix nothing: a contested name is one [mise.Lockfile.Lookup] refuses
// to lend through its sole-entry fallback, and the edited declaration no longer
// spells the version the entry records, so it cannot be matched exactly either.
//
// In particular, an entry under the exact key does not make a legacy entry
// under the short name someone else's: with a single declaration, the
// sole-entry fallback borrows the short-name entry once the exact entry is
// gone, so leaving it behind restores the vulnerable version on the next scan
// and the applied fix reads as ineffective. Pruning and enrichment answer "who
// owns this name" the same way, so an entry one of them treats as this tool's
// cannot be treated as another tool's by the other.
func miseLockKeys(root *os.Root, configRelPath, tool string) []string {
	claims, err := mise.LockClaims(root.FS(), configRelPath)
	if err != nil {
		// Ownership could not be established. The exact key keeps the reading it
		// has when nothing is known about the other configs, because enrichment
		// makes the same permissive reading of a nil claim count: leaving the
		// entry would let the fixed tool resolve back to the version the fix
		// removed. Nothing is widened beyond it.
		return []string{tool}
	}

	keys := make([]string, 0, 2)
	if !nameContested(claims, tool) {
		keys = append(keys, tool)
	}
	if _, name := mise.SplitBackend(tool); name != "" && name != tool && !nameContested(claims, name) {
		keys = append(keys, name)
	}
	return keys
}

// nameContested reports whether more than one declaration could be the owner of
// a lock entry keyed by name. The counts come from [mise.LockClaims], the same
// count that decides whether inventory may enrich from such an entry, so
// pruning and enrichment cannot disagree about who owns a name: an entry left
// in place here because it is ambiguous must also be refused there.
//
// The count spans every config sharing the lockfile, not just the one being
// edited. The lockfile is shared: a mise directory's config.toml and all of its
// conf.d drop-ins write to one mise.lock, and a lockfile may be a symlink two
// directories both write through, so a name uncontested within one fragment can
// still be claimed by a declaration in another, and pruning it would discard
// integrity metadata for a tool this fix never touched.
func nameContested(claims map[string]int, name string) bool {
	return claims[name] > 1
}

// pruneStaleMiseLock removes lock entries for the replaced versions from the
// config's sibling mise.lock, when one exists. Without this the fix looks
// applied but keeps scanning vulnerable: the extractor substitutes the locked
// version for the declared one, and lock lookup falls back to a sole stale
// entry. The entry is removed rather than updated because its per-platform
// checksums describe the old artifact; `mise install` re-locks the new
// version. When no replaced versions are known, every entry not matching the
// new version is stale by definition (the config no longer declares it).
func pruneStaleMiseLock(root *os.Root, configRelPath, tool string, currentVersions []string, newVersion string) error {
	lockRel := mise.LockfilePath(configRelPath)
	if lockRel == "" {
		return nil
	}
	data, err := fs.ReadFile(root.FS(), lockRel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", lockRel, err)
	}

	keys := miseLockKeys(root, configRelPath, tool)
	// A config left declaring one version has no use for an entry recording any
	// other, whether or not the plan named it: the keys above are only the ones
	// no other declaration claims, so nothing else installs from them. Keeping
	// them is how a fix reintroduces a version it was never asked about, since
	// the last obsolete entry left standing is a sole entry, and lock resolution
	// hands a sole entry to a declaration that matched nothing.
	//
	// The plan's versions still decide it for a declaration that stays
	// multi-version, where an entry may belong to a version the config still
	// asks for.
	exclusive := declaresOnlyNewVersion(root, configRelPath, tool, newVersion)
	// The plan and the lockfile spell versions differently (the Go runtime is
	// reported as "v1.22.12" and locked as "1.22.12"), so both comparisons go
	// through mise.SameVersion. A byte-for-byte one leaves the stale entry in
	// place, and lock resolution then keeps serving the version the fix just
	// removed.
	stale := func(version string) bool {
		if len(currentVersions) > 0 && !exclusive {
			return slices.ContainsFunc(currentVersions, func(current string) bool {
				return mise.SameVersion(current, version)
			})
		}
		return !mise.SameVersion(version, newVersion)
	}
	pruned, changed := mise.PruneLockedVersions(data, keys, stale)
	if !changed {
		return nil
	}

	info, err := fs.Stat(root.FS(), lockRel)
	if err != nil {
		return fmt.Errorf("stat %s: %w", lockRel, err)
	}
	return replaceFileAtomically(root, lockRel, pruned, info.Mode().Perm())
}

// declaresOnlyNewVersion reports whether the edited config declares exactly one
// version for tool and that version is the one the fix wrote. It is the
// question "does anything this config asks for still need a lock entry other
// than the new version's", asked of the file as it now stands rather than of
// the plan, because the plan only names the versions a finding reported and a
// lockfile may record versions no finding ever mentioned.
//
// It parses the config the way mise does, so every declaration form is
// recognized, and answers false on any read or parse failure: an unclear
// declaration must not widen pruning beyond the versions the plan named.
func declaresOnlyNewVersion(root *os.Root, configRelPath, tool, newVersion string) bool {
	data, err := fs.ReadFile(root.FS(), configRelPath)
	if err != nil {
		return false
	}
	cfg, err := mise.Parse(configRelPath, data)
	if err != nil {
		return false
	}
	for _, spec := range cfg.Tools {
		if spec.Key != tool {
			continue
		}
		return len(spec.Versions) == 1 && mise.SameVersion(spec.Versions[0], newVersion)
	}
	return false
}

// replaceFileAtomically publishes content to relPath without ever leaving the
// file truncated, resolving a symlinked path to the file it names and keeping
// the target's mode. It is [mise.ReplaceFileAtomically]: the config rewriter
// publishes its edit the same way, so the two halves of one fix cannot differ
// in whether an interrupted write can destroy the file being repaired.
func replaceFileAtomically(root *os.Root, relPath string, content []byte, perm os.FileMode) error {
	return mise.ReplaceFileAtomically(root, relPath, content, perm)
}

// resolveLinkTarget returns the path a replacement is published to: the regular
// file relPath ultimately names, following any in-repository symlink chain. It
// is [mise.ResolveLinkedPath], the same resolution that decides which configs
// share a lockfile, so the file whose claimants were counted is the file the
// edit lands on.
func resolveLinkTarget(root *os.Root, relPath string) (string, error) {
	target, _, err := mise.ResolveLinkedPath(root.FS(), relPath)
	return target, err
}

// applyActionPin rewrites a GitHub Action reference to a SHA-pinned format
// with a Dependabot-compatible version comment:
//
//	uses: owner/repo@<sha> # <tag>
//
// Delegates to githubactions.RewriteWorkflow for a single source of truth
// on the rewrite logic. The filePath must be under repoDir.
func applyActionPin(repoDir, filePath, actionRef, sha, tag string) error {
	root, err := os.OpenRoot(repoDir)
	if err != nil {
		return fmt.Errorf("opening repo root: %w", err)
	}
	defer root.Close()

	relPath, err := filepath.Rel(repoDir, filePath)
	if err != nil {
		return fmt.Errorf("computing relative path: %w", err)
	}

	return githubactions.RewriteWorkflow(root, filepath.ToSlash(relPath), []pin.Update{
		{Name: actionRef, PinnedValue: sha, VersionTag: tag},
	})
}
