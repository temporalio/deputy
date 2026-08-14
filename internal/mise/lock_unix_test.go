//go:build unix

package mise

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestLockOwnershipRefusesAPathThatIsNotAFile pins the other half of read
// containment, which is separate from where a path lands: reading a path that
// resolves to something other than a regular file is not bounded work. A fifo at
// a config path blocks the read until someone writes to it, so a scan of a
// checkout carrying one never finishes, and a character device such as /dev/zero
// has no end at all, so the read grows its buffer until the process dies. Neither
// is a config mise could use, so the answer is the same refusal an out-of-tree
// path gets.
//
// A fifo is the shape a test can build without privilege, and it is the one that
// hangs rather than allocating, so this test would time out rather than exhaust
// the machine if the guard were removed. A workspace can hold one: a checkout
// mounted from elsewhere, an extracted archive, or anything an agent container
// puts in place before a scan.
func TestLockOwnershipRefusesAPathThatIsNotAFile(t *testing.T) {
	t.Parallel()

	tree := t.TempDir()
	if err := os.WriteFile(filepath.Join(tree, "mise.toml"), []byte("[tools]\ngo = \"1.24.3\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "mise.lock"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// ".mise.toml" shares "mise.lock" with the config being scanned, so it is
	// counted as a claimant and would be read.
	if err := syscall.Mkfifo(filepath.Join(tree, ".mise.toml"), 0o644); err != nil {
		t.Skipf("cannot create a fifo: %v", err)
	}

	got, err := LockClaims(os.DirFS(tree), "mise.toml")
	if err == nil {
		t.Fatalf("LockClaims = %v, want an error refusing the fifo", got)
	}
}
