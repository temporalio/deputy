//go:build unix

package mise

import (
	"io/fs"
	"syscall"
)

// fileOwner reports the numeric owner of an existing file. The numbers live in
// the platform's stat structure, which [fs.FileInfo] only exposes through Sys,
// so a filesystem that fills in something else (an in-memory one, an archive)
// answers "unknown" and leaves ownership alone rather than guessing at zero,
// which is root.
func fileOwner(info fs.FileInfo) (uid, gid int, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}
