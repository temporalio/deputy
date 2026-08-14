//go:build unix

package mise

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

// TestReplaceFileAtomicallyPreservesOwner pins that publishing a replacement
// keeps the target's ownership, the companion of the mode it already preserves.
// The temporary belongs to the Deputy process, so a rename that publishes it
// unchanged hands the file over to whoever ran Deputy: a fix applied as root in
// an agent container leaves the developer's config and lockfile root-owned and
// no longer writable by the owner of the checkout.
//
// The group is the part an unprivileged test can move, and it is the part a
// shared workspace depends on. A temporary is created with the directory's group
// on BSD and the process's group on Linux, so a file whose group was changed to
// another group of this user comes back under the wrong one unless ownership is
// carried over deliberately.
func TestReplaceFileAtomicallyPreservesOwner(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	lockPath := filepath.Join(dir, "mise.lock")
	if err := os.WriteFile(lockPath, []byte("[[tools.go]]\nversion = \"1.22.12\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	uid, gid := ownerOf(t, lockPath)

	// Any group of this user other than the file's own: chowning to a group we
	// belong to needs no privilege, and the fixture then differs from what a
	// fresh temporary beside it would be created with.
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	other := -1
	for _, g := range groups {
		if g != gid {
			other = g
			break
		}
	}
	if other < 0 {
		t.Skipf("no group other than %d to move the fixture to (groups %v)", gid, groups)
	}
	if err := os.Chown(lockPath, uid, other); err != nil {
		t.Skipf("cannot move %s to group %d: %v", lockPath, other, err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if err := ReplaceFileAtomically(root, "mise.lock", []byte("[[tools.go]]\n"), 0o644); err != nil {
		t.Fatalf("ReplaceFileAtomically: %v", err)
	}

	gotUID, gotGID := ownerOf(t, lockPath)
	if gotUID != uid || gotGID != other {
		t.Errorf("ownership after replacement = %d:%d, want %d:%d", gotUID, gotGID, uid, other)
	}
}

// TestReplaceFileAtomicallyPublishesWhenOwnershipCannotBeCopied pins that
// carrying ownership over is best effort. Reproducing it needs privilege
// whenever the file belongs to another user or group, and a write that works
// today must not start failing because the ownership could not be copied.
func TestReplaceFileAtomicallyPublishesWhenOwnershipCannotBeCopied(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("running as root, which may chown to anyone")
	}
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "mise.lock")
	if err := os.WriteFile(lockPath, []byte("[[tools.go]]\nversion = \"1.22.12\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, gid := ownerOf(t, lockPath)
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	// A group this user does not belong to: chowning to it is refused, the same
	// refusal a file owned by another user produces.
	foreign := -1
	for candidate := 1; candidate < 4096; candidate++ {
		if candidate != gid && !slices.Contains(groups, candidate) {
			foreign = candidate
			break
		}
	}
	if foreign < 0 {
		t.Skip("no group outside this user's own to test a refused chown with")
	}
	if err := os.Chown(lockPath, os.Getuid(), foreign); err == nil {
		t.Skipf("chown to group %d was permitted, so nothing here is refused", foreign)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	if err := ReplaceFileAtomically(root, "mise.lock", []byte("[[tools.go]]\n"), 0o644); err != nil {
		t.Fatalf("ReplaceFileAtomically: %v", err)
	}
	got, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "[[tools.go]]\n" {
		t.Errorf("content after replacement = %q, want the replacement", got)
	}
}

// ownerOf reads a file's numeric owner straight from the platform, so a test of
// ownership does not read it through the helper it is testing.
func ownerOf(t *testing.T, path string) (uid, gid int) {
	t.Helper()

	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return int(st.Uid), int(st.Gid)
}
