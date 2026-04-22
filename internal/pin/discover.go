package pin

import (
	"io/fs"
	"os"
	"strings"
)

// shouldSkipDir reports whether a directory should be excluded from
// dependency discovery walks. Skips version control, dependency caches,
// and hidden directories (except .github which contains workflows).
func shouldSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor":
		return true
	}
	// Skip hidden directories except .github.
	if name != "." && strings.HasPrefix(name, ".") && name != ".github" {
		return true
	}
	return false
}

// isSymlink reports whether a directory entry is a symbolic link.
func isSymlink(d fs.DirEntry) bool {
	return d.Type()&os.ModeSymlink != 0
}

// dedupeKey returns a stable key for deduplicating discovered refs.
// Uses DisplayName (which includes subpath) to avoid colliding refs
// like github/codeql-action/init and github/codeql-action/analyze.
func dedupeKey(r Ref) string {
	return r.FilePath + "|" + r.DisplayName() + "@" + r.Version
}
