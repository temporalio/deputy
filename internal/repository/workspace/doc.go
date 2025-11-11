// Package workspace provides a safe abstraction over on-disk and in-memory
// filesystems that Deputy scans. Each workspace exposes a consistent io/fs +
// scalibr-compatible view rooted at a specific path (or virtual tree) while
// enforcing path sanitization, optional read/write capabilities, and lifecycle
// management shared by repository cloning, SBOM generation, and other targets.
package workspace
