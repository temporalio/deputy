// Package targets defines abstractions for heterogeneous scan targets (e.g.
// local directories, Git repositories, container images, SBOM documents). It
// intentionally keeps only minimal contracts so that concrete provider
// implementations can evolve elsewhere without bloating core dependency graphs.
//
// A Provider performs detection and, if applicable, materialization of a target
// into a portable fs.FS or higher level representation used by scanners. When
// multiple providers could match the same input, a Provider can implement
// PriorityProvider to influence selection order (higher priority wins).
//
// # Target Detection
//
// The DetectKind function provides deterministic target type detection based
// solely on the target string pattern. This is used by:
//   - InProcess client for routing scan requests to appropriate scanner methods
//   - Remote server for routing with security validation
//
// DetectKind intentionally does NOT perform filesystem operations or network
// validation. For richer detection with filesystem probing, git root detection,
// and ambiguity handling, see the CLI's scan_target.go implementation.
//
// # Security Validation
//
// ValidateRemoteTarget checks whether a target can be used with a remote server.
// Remote servers cannot access the client's local filesystem, so local paths,
// stdin, and local-only container transports are rejected with clear error
// messages guiding users to remote-accessible alternatives.
//
// IsLocalTarget provides a quick check for targets that require local access,
// useful for deciding whether to use in-process vs remote execution.
package targets
