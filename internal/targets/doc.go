// Package targets defines abstractions for heterogenous scan targets (e.g.
// local directories, Git repositories, container images, SBOM documents). It
// intentionally keeps only minimal contracts so that concrete provider
// implementations can evolve elsewhere without bloating core dependency graphs.
//
// A Provider performs detection and, if applicable, materialization of a target
// into a portable fs.FS or higher level representation used by scanners.
package targets
