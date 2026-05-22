package pin

import (
	"io/fs"
	"os"
	"path"
	"strings"
)

// ShouldSkipDir reports whether a directory should be excluded from
// dependency discovery walks. Skips version control, dependency caches,
// and hidden directories (except .github which contains workflows).
func ShouldSkipDir(name string) bool {
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

// IsSymlink reports whether a directory entry is a symbolic link.
func IsSymlink(d fs.DirEntry) bool {
	return d.Type()&os.ModeSymlink != 0
}

// DedupeKey returns a stable key for deduplicating discovered refs.
// Uses DisplayName (which includes subpath) to avoid colliding refs
// like github/codeql-action/init and github/codeql-action/analyze.
func DedupeKey(r Ref) string {
	return r.FilePath + "|" + r.DisplayName() + "@" + r.Version
}

// IsWorkflowFile checks if a relative path is a GitHub Actions workflow file.
func IsWorkflowFile(relPath string) bool {
	if !strings.HasPrefix(relPath, ".github/workflows/") {
		return false
	}
	ext := strings.ToLower(path.Ext(relPath))
	return ext == ".yml" || ext == ".yaml"
}

// IsCommitSHA reports whether s is a 40-character hexadecimal Git commit SHA.
func IsCommitSHA(s string) bool {
	return commitSHARe.MatchString(s)
}
