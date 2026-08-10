package remediation

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/temporalio/deputy/internal/pin"
	"github.com/temporalio/deputy/internal/pin/githubactions"
)

// IsDeputyInternalCommand checks if a command is a deputy-internal command
// that should be executed by Deputy directly rather than as a shell command.
func IsDeputyInternalCommand(cmd string) bool {
	return strings.HasPrefix(cmd, "deputy:")
}

// deputyCommandSpec describes the wire shape of one deputy-internal command.
type deputyCommandSpec struct {
	// arity is the minimum token count the command requires, including the
	// command word itself.
	arity int
	// pathArg is the index of the token naming the file the command edits.
	// Resolution and containment read it from here rather than from each
	// opcode's own branch, so an opcode cannot be applied through a position
	// preflight did not check.
	pathArg int
}

// deputyCommandSpecs is the single source of truth for which deputy-internal
// opcodes exist, how many arguments they take, and which argument names the
// file they edit. Validation, preflight, and application all read it, so a
// dry run cannot approve a command the apply path would reject.
var deputyCommandSpecs = map[string]deputyCommandSpec{
	"deputy:action:update":     {arity: 4, pathArg: 1}, // deputy:action:update <file> <owner/repo> <new-version>
	"deputy:action:pin":        {arity: 5, pathArg: 1}, // deputy:action:pin <file> <owner/repo[/subpath]> <sha> <tag>
	"deputy:dockerfile:update": {arity: 4, pathArg: 1}, // deputy:dockerfile:update <file> <image> <new-version>
}

// ValidateDeputyCommand checks that a deputy-internal command parses, names a
// known opcode, and carries enough arguments, returning the parsed tokens.
// It touches nothing on disk. Callers predicting whether ApplyDeputyCommand
// would accept a command want PreflightDeputyCommand instead, which adds the
// checks that need a repository to resolve against.
func ValidateDeputyCommand(cmd string) ([]string, error) {
	parts, err := ParseCommandArgs(cmd)
	if err != nil {
		return nil, fmt.Errorf("invalid command: %w", err)
	}

	spec, known := deputyCommandSpecs[parts[0]]
	if !known {
		return nil, fmt.Errorf("unknown deputy command: %s", parts[0])
	}
	if len(parts) < spec.arity {
		return nil, fmt.Errorf("invalid %s command: expected %d parts, got %d", parts[0], spec.arity, len(parts))
	}
	return parts, nil
}

// PreflightDeputyCommand reports whether ApplyDeputyCommand would accept a
// command, without applying it. It runs every check the apply path runs before
// it touches a file: parsing, the opcode vocabulary, arity, and containment of
// the target path within repoDir. A dry run that skipped the containment check
// would report a step naming ../outside/ci.yml as applicable and then watch
// execution refuse it, so the two share one implementation and one message.
func PreflightDeputyCommand(repoDir, cmd string) error {
	_, _, err := resolveDeputyCommand(repoDir, cmd)
	return err
}

// resolveDeputyCommand validates a deputy-internal command and resolves the
// file it edits against repoDir, returning the parsed tokens and the contained
// absolute path. It is the one place that knows where a command's target path
// lives, so preflight and application cannot disagree about which path is
// checked or how a refusal reads.
func resolveDeputyCommand(repoDir, cmd string) ([]string, string, error) {
	parts, err := ValidateDeputyCommand(cmd)
	if err != nil {
		return nil, "", err
	}
	spec := deputyCommandSpecs[parts[0]]
	file, err := safeJoinPath(repoDir, parts[spec.pathArg])
	if err != nil {
		return nil, "", fmt.Errorf("invalid file path: %w", err)
	}
	return parts, file, nil
}

// ApplyDeputyCommand executes a deputy-internal command.
// Returns an error if the command is not recognized or fails.
func ApplyDeputyCommand(repoDir, cmd string) error {
	parts, file, err := resolveDeputyCommand(repoDir, cmd)
	if err != nil {
		return err
	}

	switch parts[0] {
	case "deputy:action:update":
		// Format: deputy:action:update <file> <owner/repo> <new-version>
		actionRef := parts[2]
		newVersion := parts[3]
		return applyActionUpdate(file, actionRef, newVersion)

	case "deputy:action:pin":
		// Format: deputy:action:pin <file> <owner/repo[/subpath]> <sha> <tag>
		actionRef := parts[2]
		sha := parts[3]
		tag := parts[4]
		return applyActionPin(repoDir, file, actionRef, sha, tag)

	case "deputy:dockerfile:update":
		// Format: deputy:dockerfile:update <file> <image> <new-version>
		image := parts[2]
		newVersion := parts[3]
		return applyDockerfileUpdate(file, image, newVersion)

	default:
		// Unreachable: ValidateDeputyCommand rejects unknown opcodes, and
		// this switch must stay exhaustive over deputyCommandSpecs.
		return fmt.Errorf("unknown deputy command: %s", parts[0])
	}
}

// resolveBaseDir returns the absolute, symlink-resolved form of a repository
// directory. Every path a deputy-internal command produces or consumes is
// expressed against this form, so that two spellings of one directory (the
// caller's /var/folders/... and the real /private/var/folders/...) cannot be
// mistaken for two different directories.
//
// A base that does not exist yet keeps its unresolved absolute form, since
// there is nothing to resolve against; containment is still checked lexically.
func resolveBaseDir(baseDir string) (string, error) {
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("invalid base directory: %w", err)
	}
	if realBase, err := filepath.EvalSymlinks(absBase); err == nil {
		absBase = realBase
	}
	return absBase, nil
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
	absBase, err := resolveBaseDir(baseDir)
	if err != nil {
		return "", err
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

// applyActionPin rewrites a GitHub Action reference to a SHA-pinned format
// with a Dependabot-compatible version comment:
//
//	uses: owner/repo@<sha> # <tag>
//
// Delegates to githubactions.RewriteWorkflow for a single source of truth
// on the rewrite logic. The filePath must be under repoDir.
//
// The root is opened on the resolved repoDir, not the caller's spelling of it.
// filePath arrives symlink-resolved from resolveDeputyCommand, so relating it
// to an unresolved repoDir yields a path that climbs out of the root and back
// in ("../../../private/var/..."), which os.Root then refuses. That makes the
// opcode fail on any checkout reached through a symlink, which on macOS is
// every path under /tmp and /var.
func applyActionPin(repoDir, filePath, actionRef, sha, tag string) error {
	base, err := resolveBaseDir(repoDir)
	if err != nil {
		return err
	}

	root, err := os.OpenRoot(base)
	if err != nil {
		return fmt.Errorf("opening repo root: %w", err)
	}
	defer root.Close()

	relPath, err := filepath.Rel(base, filePath)
	if err != nil {
		return fmt.Errorf("computing relative path: %w", err)
	}

	return githubactions.RewriteWorkflow(root, filepath.ToSlash(relPath), []pin.Update{
		{Name: actionRef, PinnedValue: sha, VersionTag: tag},
	})
}
