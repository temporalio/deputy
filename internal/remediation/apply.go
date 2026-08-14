package remediation

import (
	"context"
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
	// validateArgs checks the arguments only this opcode understands, against
	// the same rule the code that applies them enforces. Arity says a
	// deputy:action:pin command carries a SHA and a tag; only this says the
	// SHA has to be one. A nil hook means the opcode's apply path asks nothing
	// of its arguments beyond their count, so there is nothing to share.
	validateArgs func(parts []string) error
	// matchTarget answers, from the target's current bytes, whether the edit
	// would find anything to change, using the same matching the apply path
	// uses. It is what stops a preview from promising an edit against a file
	// that has moved on since the plan was written. filePath names the target
	// in the refusal only; nothing here writes.
	matchTarget func(parts []string, filePath string, content []byte) error
}

// deputyCommandSpecs is the single source of truth for which deputy-internal
// opcodes exist, how many arguments they take, and which argument names the
// file they edit. Validation, preflight, and application all read it, so a
// dry run cannot approve a command the apply path would reject.
var deputyCommandSpecs = map[string]deputyCommandSpec{
	// deputy:action:update <file> <owner/repo> <new-version>
	"deputy:action:update": {arity: 4, pathArg: 1, matchTarget: matchActionUpdate},
	// deputy:action:pin <file> <owner/repo[/subpath]> <sha> <tag>
	"deputy:action:pin": {arity: 5, pathArg: 1, validateArgs: validateActionPin, matchTarget: matchActionPin},
	// deputy:dockerfile:update <file> <image> <new-version>
	"deputy:dockerfile:update": {arity: 4, pathArg: 1, matchTarget: matchDockerfileUpdate},
	// deputy:mise:update <file> <tool> <new-version> [<current-version>...]
	//
	// No matchTarget: the mise rewrite has no dry-run form. It decides what to
	// change while walking the config's lines and publishes the result in the
	// same pass, and its verdict also depends on the sibling lockfile, so the
	// only way to ask it "would this change anything" is to let it write.
	// Restating its rules here is what a matchTarget would amount to, and a
	// second copy of them is exactly what lets preflight and application
	// disagree, which is what this table exists to prevent. Preflight therefore
	// checks this opcode's tokens, its target's containment, and that the target
	// is a file that can be edited, and leaves the content verdict to the run;
	// giving pinmise a plan-only entry point is the way to close that, not a
	// paraphrase of it here.
	"deputy:mise:update": {arity: 4, pathArg: 1},
}

// matchActionUpdate reports whether a deputy:action:update command has an edit
// to make, by computing the very rewrite the apply path computes and throwing
// the result away. Running the real thing is what makes the two verdicts
// identical rather than merely similar.
func matchActionUpdate(parts []string, filePath string, content []byte) error {
	_, err := planActionUpdate(filePath, content, parts[2], parts[3])
	return err
}

// matchDockerfileUpdate is matchActionUpdate for deputy:dockerfile:update.
func matchDockerfileUpdate(parts []string, filePath string, content []byte) error {
	_, err := planDockerfileUpdate(filePath, content, parts[2], parts[3])
	return err
}

// matchActionPin refuses a deputy:action:pin command whose workflow does not
// use the action at all.
//
// This opcode needs its own check rather than a dry rewrite, because
// githubactions.RewriteWorkflow is deliberately silent when it changes
// nothing: that is what keeps re-pinning an already-pinned workflow a success.
// The silence covers both "already done" and "the action is not here", and
// only the second is a step that cannot be applied. Left unasked, the step
// reported as completed while the workflow kept its unpinned reference.
func matchActionPin(parts []string, filePath string, content []byte) error {
	actionRef := parts[2]
	referenced, err := githubactions.ReferencesAction(content, actionRef)
	if err != nil {
		return err
	}
	if !referenced {
		return fmt.Errorf("no matches found for action %s in %s", actionRef, filePath)
	}
	return nil
}

// actionPinUpdate builds the rewrite a deputy:action:pin command asks for from
// its tokens. Validation and application both go through it, so the arguments
// preflight judges are the arguments the rewrite receives.
func actionPinUpdate(parts []string) pin.Update {
	return pin.Update{Name: parts[2], PinnedValue: parts[3], VersionTag: parts[4]}
}

// validateActionPin checks a deputy:action:pin command's action reference, SHA,
// and version tag against the rule githubactions.RewriteWorkflow enforces on the
// same three values. It borrows that package's validator rather than restating
// it, because a second copy of "what counts as a SHA" is what would let a dry
// run accept a pin the rewrite refuses.
func validateActionPin(parts []string) error {
	return githubactions.ValidateUpdate(actionPinUpdate(parts))
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
// [filepath.Rel] and [escapesBase] rather than a string prefix, so a sibling
// whose name merely starts with the directory's ("/w/repo" and "/w/repo-fork")
// is not read as nested, and a directory legitimately named "..data", as
// Kubernetes secret mounts are, is read as nested rather than as an escape.
//
// A pair of paths that cannot be related at all (separate volumes on Windows) is
// reported as contained, keeping the answer conservative: two trees are only
// allowed to run at once when they are known not to overlap.
func contains(dir, sub string) bool {
	rel, err := filepath.Rel(dir, sub)
	if err != nil {
		return true
	}
	return !escapesBase(rel)
}

// PreflightDeputyCommand reports whether ApplyDeputyCommand would accept a
// command, without applying it. It runs every check the apply path runs before
// it writes: parsing, the opcode vocabulary, arity, containment of the target
// path within repoDir, that the target is a file the apply path could edit, the
// arguments only that opcode understands, and whether the target's current
// content holds anything the edit would change. A dry run that skipped the
// containment check would report a step naming ../outside/ci.yml as applicable
// and then watch execution refuse it, so the two share one implementation and
// one message.
//
// The content check is what a plan needs most, because a plan outlives the tree
// it was built against: someone bumps the action by hand or drops the build
// stage, and the stored step still names what used to be there. It reads the
// target and writes nothing, running the opcode's own rewrite and discarding
// the result, so preflight cannot reach a different verdict from the run. Only
// the opcodes whose rewrite can be computed without publishing it have one; see
// [deputyCommandSpecs] for which, and why deputy:mise:update does not.
func PreflightDeputyCommand(repoDir, cmd string) error {
	_, _, err := resolveDeputyCommand(repoDir, cmd)
	return err
}

// resolveDeputyCommand validates a deputy-internal command and resolves the
// file it edits against repoDir, returning the parsed tokens and the contained
// absolute path. It is the one place that knows where a command's target path
// lives, so preflight and application cannot disagree about which path is
// checked or how a refusal reads.
//
// The opcode's own argument check runs last, in the position the apply path
// reaches it: containment and the target's kind are decided before any argument
// is read there too, so a command that both escapes the repository and carries a
// malformed SHA is refused for the escape, which is the refusal worth reporting.
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
	if err := requireEditableFile(file); err != nil {
		return nil, "", err
	}
	if spec.validateArgs != nil {
		if err := spec.validateArgs(parts); err != nil {
			return nil, "", fmt.Errorf("invalid %s command: %w", parts[0], err)
		}
	}
	// Last, because it is the only check that reads the file: everything a
	// refusal can be decided from the command alone is decided first, so a
	// command that is malformed and also aimed at the wrong file is refused
	// for being malformed.
	if spec.matchTarget != nil {
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, "", fmt.Errorf("reading %s: %w", file, err)
		}
		if err := spec.matchTarget(parts, file, content); err != nil {
			return nil, "", err
		}
	}
	return parts, file, nil
}

// requireEditableFile refuses a deputy-internal command whose target the apply
// path could not edit: one that does not exist, and one that exists but is not
// a regular file.
//
// Existence is checked here, rather than left to the opcode's own read, because
// preflight and application have to agree. Every opcode opens its target as its
// first act, so a command naming a file that is not there fails immediately;
// leaving that to the read meant a dry run reported the edit as one that would
// apply, counted the step as satisfied, and let its dependents be previewed
// against a plan that cannot be applied at all. Plans name paths a generator
// inferred from a scan, so a stale or renamed target is a mistake worth catching
// in the preview rather than the run.
//
// The regular-file requirement is about the execution timeout. Every opcode
// reads its target whole and writes it back, and neither operation is
// interruptible once it has begun: opening a FIFO that has no writer blocks
// until one appears, and a context cannot cancel a read already blocked in the
// kernel. A plan naming a FIFO would therefore hold its step, and the RPC
// serving it, past the timeout no matter how carefully the apply path checks its
// deadline. Refusing up front is what keeps that timeout meaningful.
//
// Workflow files, action manifests, Dockerfiles, and mise configs are regular
// files that a plan was generated from, so this rejects nothing a current plan
// asks for. A mise config reached through an in-repository symlink is judged by
// the file the link names, since that is the file the edit lands on. The refusal
// names the path it could not use, so it says what the read would have.
func requireEditableFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("cannot edit %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return nil
}

// ApplyDeputyCommand executes a deputy-internal command.
// Returns an error if the command is not recognized or fails.
//
// Nothing is written until the command has been through
// [resolveDeputyCommand], the same checks [PreflightDeputyCommand] runs, so a
// step a caller was told could not be applied cannot be applied anyway, and a
// command whose arguments were never checked cannot reach a rewrite.
//
// The edit is then serialized by [fileEdits] against every other one in the
// process that could touch the same files, so a command reads the file its
// predecessor wrote rather than the bytes they both started from. Edits to
// unrelated working trees proceed at once. The guard is taken after the checks
// rather than before them because every opcode re-reads its target inside the
// guarded section: the checks decide whether an edit is worth attempting, and
// the bytes it is computed from are read under the guard, so a verdict reached
// just before a predecessor's write cannot turn into a lost update. What it can
// turn into is a refusal from the run that preflight did not predict, which is
// the direction that costs nothing.
//
// ctx bounds the edit. A deputy-internal command is applied in process rather
// than as a subprocess, so nothing else enforces the caller's deadline on it:
// the execution timeout an RPC or a fix run advertises covers these steps only
// because this path checks ctx itself. The checks bracket the filesystem work
// (see [ensureLive]), so a read that outlived the deadline cannot go on to
// modify the workspace.
func ApplyDeputyCommand(ctx context.Context, repoDir, cmd string) error {
	parts, file, err := resolveDeputyCommand(repoDir, cmd)
	if err != nil {
		return err
	}

	defer fileEdits.guard(repoDir)()

	switch parts[0] {
	case "deputy:action:update":
		// Format: deputy:action:update <file> <owner/repo> <new-version>
		actionRef := parts[2]
		newVersion := parts[3]
		return applyActionUpdate(ctx, file, actionRef, newVersion)

	case "deputy:action:pin":
		// Format: deputy:action:pin <file> <owner/repo[/subpath]> <sha> <tag>
		return applyActionPin(ctx, repoDir, file, actionPinUpdate(parts))

	case "deputy:mise:update":
		// Format: deputy:mise:update <file> <tool> <new-version> [<current-version>...]
		// The current versions target the vulnerable elements when the tool
		// declares multiple versions in an array.
		//
		// Containment was decided by resolveDeputyCommand, but the edit keeps
		// working with the detected path rather than the symlink-resolved
		// target it returned: the manifest's own location is what determines
		// its sibling lockfile.
		//
		// The deadline is checked once, here, and not again between the config
		// rewrite and the lockfile prune. Those two writes are halves of one
		// fix, and mise's rewriter takes no context, so abandoning the second
		// on an expired deadline would leave the workspace holding a config
		// that declares the new version beside a lock entry that still installs
		// the old one, having told the caller the step did not run. The rewrite
		// is idempotent for exactly this reason: the recovery is a retry, not
		// an abort partway through.
		if err := ensureLive(ctx, "editing", file); err != nil {
			return err
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
		image := parts[2]
		newVersion := parts[3]
		return applyDockerfileUpdate(ctx, file, image, newVersion)

	default:
		// Unreachable: ValidateDeputyCommand rejects unknown opcodes, and
		// this switch must stay exhaustive over deputyCommandSpecs.
		return fmt.Errorf("unknown deputy command: %s", parts[0])
	}
}

// ensureLive reports ctx's cancellation as an error naming the file the step
// was about to touch and the operation it was about to perform.
//
// Every deputy-internal edit is checked twice: once before reading, so an
// already expired deadline costs no filesystem work, and once after the read and
// before the write, which is the check that matters. The two opcodes that read
// and write here call this function for both; deputy:action:pin delegates its
// write to githubactions.RewriteWorkflow, which makes the second check itself
// with the same context. A rewrite that took longer than
// the caller allowed must not still be committed, because the caller has by
// then been told the step timed out and is entitled to treat the workspace as
// untouched by it.
//
// deputy:mise:update is checked once, before its first read, and the reason is
// in [ApplyDeputyCommand]: its edit is two writes that have to happen together,
// so the second check would have to abort between them.
func ensureLive(ctx context.Context, operation, filePath string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("not %s %s: %w", operation, filePath, err)
	}
	return nil
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
	if err != nil || escapesBase(rel) {
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
	if err != nil || escapesBase(finalRel) {
		return "", fmt.Errorf("path escapes base directory after symlink resolution")
	}

	return realJoined, nil
}

// escapesBase reports whether a path relative to a base directory leaves it,
// which is true only when its first component is the parent directory. The test
// is on the component and not on the text, because a name may begin with two
// dots and still be an ordinary directory: Kubernetes mounts a projected secret
// or configmap through "..data", so a repository scanned from such a mount
// declares "..data/mise.toml" and a prefix test refused Deputy's own generated
// fix command.
//
// A genuine escape still is one. "..", anything under "../", and a Windows
// "..\" are all rejected, and [filepath.Rel] has already cleaned the path, so
// an interior "a/../.." has been reduced to whatever it really names before it
// reaches here.
func escapesBase(rel string) bool {
	return rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
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
	if escapesBase(rel) {
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
func applyActionUpdate(ctx context.Context, filePath, actionRef, newVersion string) error {
	if err := ensureLive(ctx, "reading", filePath); err != nil {
		return err
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", filePath, err)
	}

	updated, err := planActionUpdate(filePath, content, actionRef, newVersion)
	if err != nil {
		return err
	}

	// Write back
	if err := ensureLive(ctx, "writing", filePath); err != nil {
		return err
	}
	if err := os.WriteFile(filePath, updated, 0644); err != nil {
		return fmt.Errorf("writing %s: %w", filePath, err)
	}

	return nil
}

// planActionUpdate computes the rewritten workflow for a deputy:action:update
// command, returning an error when the content holds nothing the update would
// change. It touches no files, so preflight can run it to learn the verdict
// the apply path will reach without reaching it.
//
// filePath names the target in the error only. Preflight and application both
// report the refusal this produces, so the two say the same thing.
func planActionUpdate(filePath string, content []byte, actionRef, newVersion string) ([]byte, error) {
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
		return nil, fmt.Errorf("compiling SHA+comment regex: %w", err)
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
			return nil, fmt.Errorf("compiling regex: %w", err)
		}

		replacement := fmt.Sprintf("${1}${2}@%s${4}", newVersion)
		newContent := re.ReplaceAllString(contentStr, replacement)
		if newContent != contentStr {
			contentStr = newContent
			modified = true
		}
	}

	if !modified {
		return nil, fmt.Errorf("no matches found for action %s in %s", actionRef, filePath)
	}
	return []byte(contentStr), nil
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
func applyDockerfileUpdate(ctx context.Context, filePath, image, newVersion string) error {
	if err := ensureLive(ctx, "reading", filePath); err != nil {
		return err
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", filePath, err)
	}

	updated, err := planDockerfileUpdate(filePath, content, image, newVersion)
	if err != nil {
		return err
	}

	if err := ensureLive(ctx, "writing", filePath); err != nil {
		return err
	}
	if err := os.WriteFile(filePath, updated, 0644); err != nil {
		return fmt.Errorf("writing %s: %w", filePath, err)
	}

	return nil
}

// planDockerfileUpdate computes the rewritten Dockerfile for a
// deputy:dockerfile:update command, returning an error when no FROM
// instruction names the image. Like planActionUpdate it touches no files, so
// preflight reaches the apply path's verdict without reaching its write, and
// filePath appears only in the error both of them report.
func planDockerfileUpdate(filePath string, content []byte, image, newVersion string) ([]byte, error) {
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
		return nil, fmt.Errorf("no FROM %s found in %s", image, filePath)
	}

	// Preserve the original line endings.
	return []byte(strings.Join(lines, "\n")), nil
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
//
// That symmetry decides the failure case too: with ownership unresolved every
// name is contested and nothing is pruned. Both readers of a lockfile answer an
// unresolved count by setting the whole lockfile aside rather than by reading it
// permissively (misex.Extract drops enrichment, Strategy.Discover drops the
// locked version), so a preserved entry cannot be served back to the edited
// declaration and the fix does not read as ineffective. Pruning on the guess
// would delete integrity metadata a config nobody edited still installs from,
// and that is the loss that does not undo itself: once whatever obscured
// ownership is repaired, an entry left standing is visible again and the next
// fix removes it, while checksums deleted on a guess are gone from the
// repository.
func miseLockKeys(root *os.Root, configRelPath, tool string) []string {
	claims, err := mise.LockClaims(root.FS(), configRelPath)
	if err != nil {
		return nil
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
				return mise.SameVersion(tool, current, version)
			})
		}
		return !mise.SameVersion(tool, version, newVersion)
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

// declaresOnlyNewVersion reports whether every version the edited config still
// declares for tool is the one the fix wrote. It is the question "does anything
// this config asks for still need a lock entry other than the new version's",
// asked of the file as it now stands rather than of the plan, because the plan
// only names the versions a finding reported and a lockfile may record versions
// no finding ever mentioned.
//
// Duplicates answer yes, which is why the question is about content rather than
// arity. An update that replaces several vulnerable versions with one target
// leaves `go = ["1.24.3", "1.24.3"]`, a declaration that needs exactly one lock
// entry however many times it spells it; reading two elements as "still
// multi-version" left a historical entry standing as the only one, and lock
// resolution lends a sole entry to a declaration that matched nothing, so the
// next scan reported the fixed tool at a version older than the one flagged.
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
		// Every declared version, not one of them: a declaration counts as
		// exclusive when nothing it asks for is any other version. Counting
		// declarations instead missed the array whose elements converge, since
		// an update that replaces two vulnerable versions with one target
		// leaves that target declared twice.
		return len(spec.Versions) > 0 && !slices.ContainsFunc(spec.Versions, func(v string) bool {
			return !mise.SameVersion(tool, v, newVersion)
		})
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
//
// The root is opened on the resolved repoDir, not the caller's spelling of it.
// filePath arrives symlink-resolved from resolveDeputyCommand, so relating it
// to an unresolved repoDir yields a path that climbs out of the root and back
// in ("../../../private/var/..."), which os.Root then refuses. That makes the
// opcode fail on any checkout reached through a symlink, which on macOS is
// every path under /tmp and /var.
//
// The deadline is checked twice, as it is for the other two opcodes: once here
// before any filesystem work, and once inside the rewrite between its read and
// its write. The second check is the one that matters, since a rewrite that
// outlived the caller's deadline must not still be committed to a workspace the
// caller has been told is untouched. Reaching it did not require a context on
// [pin.Strategy].Rewrite, whose signature every strategy shares: the rewrite
// itself is a package-level function, so it can take a context while the
// interface method keeps passing a background one.
func applyActionPin(ctx context.Context, repoDir, filePath string, update pin.Update) error {
	if err := ensureLive(ctx, "rewriting", filePath); err != nil {
		return err
	}

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

	if err := githubactions.RewriteWorkflow(ctx, root, filepath.ToSlash(relPath), []pin.Update{update}); err != nil {
		return fmt.Errorf("pinning %s in %s: %w", update.Name, filePath, err)
	}
	return nil
}
