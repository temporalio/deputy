// Package targets defines abstractions for heterogeneous scan targets (e.g.
// local directories, Git repositories, container images, SBOM documents). It
// intentionally keeps only minimal contracts so that concrete provider
// implementations can evolve elsewhere without bloating core dependency graphs.
//
// A Provider performs detection and, if applicable, materialization of a target
// into a portable fs.FS or higher level representation used by scanners. When
// multiple providers could match the same input, a Provider can implement
// PriorityProvider to influence selection order (higher priority wins).
package targets
