package mise

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
)

// ReplaceFileAtomically writes content to relPath by filling a temporary
// sibling and renaming it over the target, so the file is either its old
// content or its new content and never a truncated mix. Truncating in place
// would let a full disk or an interrupt leave a file empty, silently losing the
// integrity metadata of every unrelated tool in a lockfile or the whole of a
// hand-written config, and a retry could not recover because the next run would
// read the damaged file and find nothing left to edit.
//
// Every writer of a mise file goes through it, the config rewriter and the
// lockfile pruner alike: the two are published together as one fix, so a config
// that can be left half-written is a fix that can destroy the file it was asked
// to repair. The temporary file is created in the same directory so the rename
// stays on one filesystem, and is removed on any failure.
//
// Each call gets its own randomly named temporary. A shared fixed name would
// make two concurrent applies collide: one would unlink the other's open
// temporary, refill the name, and have the refill renamed into place by the
// first process mid-write, publishing partial content. A hard interrupt can
// leave a stray temporary behind, which is the same trade os.CreateTemp makes
// and is preferable to deleting a file another process is writing.
//
// A symlinked relPath is resolved first, so the replacement lands on the file
// the link points at rather than on the link itself. Reads follow the link, so
// writing anywhere else would publish the edit to a file nobody reads.
func ReplaceFileAtomically(root *os.Root, relPath string, content []byte, perm os.FileMode) error {
	relPath, err := linkTarget(root, relPath)
	if err != nil {
		return err
	}
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

// linkTarget returns the path a replacement should be published to: the regular
// file relPath ultimately names, following any in-repository symlink chain.
// Renaming over a link's own pathname would swap the link for a regular file,
// so the shared target it pointed at keeps whatever it had. For a lockfile that
// means every other config resolving through that target still gets the version
// the fix just removed, while the repository silently loses the layout choice
// the link expressed.
//
// The chain is followed by [ResolveLinkedPath], the same resolution that decides
// which configs share a lockfile, so the file whose claimants were counted is
// the file this writes to. Resolution runs against the os.Root's own
// filesystem, so it cannot be talked into publishing outside the tree being
// fixed.
func linkTarget(root *os.Root, relPath string) (string, error) {
	target, _, err := ResolveLinkedPath(root.FS(), relPath)
	return target, err
}

// createUniqueTemp opens a new file that no other process holds, in the same
// directory as relPath so a later rename stays on one filesystem. O_EXCL is
// what makes the name exclusively ours; a name already taken is retried rather
// than cleared, so a concurrent apply's in-flight temporary is never unlinked.
//
// The creation mode is only a request: the process umask reduces it, so a
// temporary asked for as 0664 is really 0644 under the usual 0022. Renaming
// that over a group-writable lockfile would quietly narrow the file, and in a
// shared workspace the next writer loses access it had. The mode is therefore
// set explicitly on the open file, which the umask does not touch, before any
// content reaches it.
func createUniqueTemp(root *os.Root, relPath string, perm os.FileMode) (*os.File, string, error) {
	dir := path.Dir(relPath)
	base := "." + path.Base(relPath) + ".deputy-"
	for range 100 {
		tmpRel := path.Join(dir, base+rand.Text())
		f, err := root.OpenFile(tmpRel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
		if err == nil {
			if err := f.Chmod(perm); err != nil {
				_ = f.Close()
				_ = root.Remove(tmpRel)
				return nil, "", fmt.Errorf("setting mode on %s: %w", tmpRel, err)
			}
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
