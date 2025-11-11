// Package repository coordinates go-git repositories with Deputy workspaces.
// It centralizes cloning, opening, and cleanup logic so callers always receive
// a Source that pairs a *git.Repository with a workspace.FS (either backed by
// the host filesystem or an in-memory scratch tree). Higher level commands use
// this package to clone repositories into temporary directories, perform
// read-only in-memory scans, or attach to an existing checkout while relying on
// Source.Close to release filesystem resources deterministically.
package repository
