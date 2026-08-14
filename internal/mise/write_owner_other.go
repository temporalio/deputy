//go:build !unix

package mise

import "io/fs"

// fileOwner reports that ownership is unknown on platforms without Unix owner
// semantics, so publication carries over what it can (the mode) and changes
// nothing it cannot describe.
func fileOwner(fs.FileInfo) (uid, gid int, ok bool) {
	return 0, 0, false
}
