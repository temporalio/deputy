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
		file, err := safeJoinPath(repoDir, parts[1])
		if err != nil {
			return fmt.Errorf("invalid file path: %w", err)
		}
		tool := parts[2]
		newVersion := parts[3]
		currentVersions := parts[4:]
		return applyMiseUpdate(repoDir, file, tool, currentVersions, newVersion)

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
// the vulnerable version the fix just removed. The filePath must be under
// repoDir; currentVersions may be empty when unknown (array declarations then
// fail closed rather than guess).
func applyMiseUpdate(repoDir, filePath, tool string, currentVersions []string, newVersion string) error {
	root, err := os.OpenRoot(repoDir)
	if err != nil {
		return fmt.Errorf("opening repo root: %w", err)
	}
	defer root.Close()

	// filePath comes from safeJoinPath and is symlink-resolved; resolve the
	// base the same way so the relative path stays inside the root.
	base, err := filepath.Abs(repoDir)
	if err != nil {
		return fmt.Errorf("resolving repo directory: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(base); err == nil {
		base = resolved
	}
	relPath, err := filepath.Rel(base, filePath)
	if err != nil {
		return fmt.Errorf("computing relative path: %w", err)
	}

	relPath = filepath.ToSlash(relPath)
	if err := pinmise.RewriteToolVersion(root, relPath, tool, currentVersions, newVersion); err != nil {
		return fmt.Errorf("updating mise config: %w", err)
	}
	if err := pruneStaleMiseLock(root, relPath, tool, currentVersions, newVersion); err != nil {
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
// an unambiguous fallback: the lock has no entry under the exact key, and the
// config does not declare that short name as a tool of its own.
func miseLockKeys(root *os.Root, configRelPath string, lockData []byte, tool string) []string {
	_, name := mise.SplitBackend(tool)
	if name == "" || name == tool {
		return []string{tool}
	}
	if mise.HasLockedTool(lockData, tool) || configDeclaresMiseTool(root, configRelPath, name) {
		return []string{tool}
	}
	return []string{tool, name}
}

// configDeclaresMiseTool reports whether the config at relPath declares key as
// a tool in its own right. An unreadable or unparsable config is reported as
// declaring the tool, so an ambiguous case never widens lock pruning.
func configDeclaresMiseTool(root *os.Root, relPath, key string) bool {
	data, err := fs.ReadFile(root.FS(), relPath)
	if err != nil {
		return true
	}
	cfg, err := mise.Parse(relPath, data)
	if err != nil {
		return true
	}
	return slices.ContainsFunc(cfg.Tools, func(t mise.ToolSpec) bool { return t.Key == key })
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
	f, err := root.OpenFile(lockRel, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("writing %s: %w", lockRel, err)
	}
	_, writeErr := f.Write(pruned)
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return fmt.Errorf("writing %s: %w", lockRel, writeErr)
	}
	return nil
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
