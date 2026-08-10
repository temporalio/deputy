package remediation

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

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

// ApplyDeputyCommand executes a deputy-internal command.
// Returns an error if the command is not recognized or fails.
func ApplyDeputyCommand(repoDir, cmd string) error {
	parts, err := ParseCommandArgs(cmd)
	if err != nil {
		return fmt.Errorf("invalid command: %w", err)
	}

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
// just edited. It is deliberately narrow: only the configured key is pruned,
// because a config can declare both a backend-qualified tool and its short
// name as separate tools (`"npm:node"` and `node`) whose lock entries are
// independent, and pruning both would discard integrity metadata for a
// declaration that was never edited. The backend-stripped name is used only as
// an unambiguous fallback: the lock has no entry under the exact key, and no
// other declaration in the config could own that short name.
func miseLockKeys(root *os.Root, configRelPath string, lockData []byte, tool string) []string {
	_, name := mise.SplitBackend(tool)
	if name == "" || name == tool {
		return []string{tool}
	}
	if mise.HasLockedTool(lockData, tool) || shortNameContested(root, configRelPath, tool, name) {
		return []string{tool}
	}
	return []string{tool, name}
}

// shortNameContested reports whether any declaration in the config other than
// tool could be the owner of a legacy lock entry keyed by the short name.
// Ownership is decided on the backend-stripped name rather than a literal
// match, because every qualified declaration that strips to the same name is
// an equally plausible claimant: with both "npm:foo" and "ubi:foo" declared,
// no bare "foo" key appears in the config, yet a [[tools.foo]] lock entry
// could belong to either, and pruning it while fixing one would discard the
// other's checksums. An unreadable or unparsable config counts as contested,
// so an ambiguous case never widens lock pruning.
func shortNameContested(root *os.Root, relPath, tool, name string) bool {
	data, err := fs.ReadFile(root.FS(), relPath)
	if err != nil {
		return true
	}
	cfg, err := mise.Parse(relPath, data)
	if err != nil {
		return true
	}
	return slices.ContainsFunc(cfg.Tools, func(t mise.ToolSpec) bool {
		return t.Key != tool && t.Name == name
	})
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

	keys := miseLockKeys(root, configRelPath, data, tool)
	stale := func(version string) bool {
		if len(currentVersions) > 0 {
			return slices.Contains(currentVersions, version)
		}
		return version != newVersion
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

// replaceFileAtomically writes content to relPath by filling a temporary
// sibling and renaming it over the target, so the file is either its old
// content or its new content and never a truncated mix. Truncating in place
// would let a full disk or an interrupt leave a lockfile empty, silently
// losing the integrity metadata of every unrelated tool, and a retry could not
// recover because the pruner would read the damaged file and find nothing left
// to prune. The temporary file is created in the same directory so the rename
// stays on one filesystem, and is removed on any failure.
//
// Each call gets its own randomly named temporary. A shared fixed name would
// make two concurrent applies collide: one would unlink the other's open
// temporary, refill the name, and have the refill renamed into place by the
// first process mid-write, publishing partial content. A hard interrupt can
// leave a stray temporary behind, which is the same trade os.CreateTemp makes
// and is preferable to deleting a file another process is writing.
func replaceFileAtomically(root *os.Root, relPath string, content []byte, perm os.FileMode) error {
	f, tmpRel, err := createUniqueTemp(root, relPath, perm)
	if err != nil {
		return err
	}
	if writeErr := writeAndSync(f, content); writeErr != nil {
		_ = root.Remove(tmpRel)
		return fmt.Errorf("writing %s: %w", tmpRel, writeErr)
	}
	if err := root.Rename(tmpRel, relPath); err != nil {
		_ = root.Remove(tmpRel)
		return fmt.Errorf("replacing %s: %w", relPath, err)
	}
	return nil
}

// createUniqueTemp opens a new file that no other process holds, in the same
// directory as relPath so a later rename stays on one filesystem. O_EXCL is
// what makes the name exclusively ours; a name already taken is retried rather
// than cleared, so a concurrent apply's in-flight temporary is never unlinked.
func createUniqueTemp(root *os.Root, relPath string, perm os.FileMode) (*os.File, string, error) {
	dir := path.Dir(relPath)
	base := "." + path.Base(relPath) + ".deputy-"
	for range 100 {
		tmpRel := path.Join(dir, base+rand.Text())
		f, err := root.OpenFile(tmpRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err == nil {
			return f, tmpRel, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, "", fmt.Errorf("creating %s: %w", tmpRel, err)
		}
	}
	return nil, "", fmt.Errorf("creating a temporary file beside %s: too many name collisions", relPath)
}

// writeAndSync writes content to f and flushes it to stable storage before
// closing, so a rename cannot publish a file whose contents are still buffered.
func writeAndSync(f *os.File, content []byte) error {
	_, err := f.Write(content)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
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
