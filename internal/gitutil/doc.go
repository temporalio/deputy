// Package git contains enhanced Git reference resolution and diff utilities
// built on top of go-git. It adds higher level ergonomics required by the
// deputy CLI including:
//   - Flexible reference parsing (branches, tags, SHAs, remote refs, pseudo WORKING ref)
//   - Time-qualified revision selection (HEAD@{1.week.ago} style) via ResolveRevisionEnhanced
//   - Detection of dependency file changes for optimization (CheckFilesChanged)
//   - Heuristics for default branch discovery in varied repository topologies
//   - Similarity scoring and suggestion generation for mistyped references
//
// The functions are side‑effect free (except repository reads) and suitable for
// reuse in other analysis workflows.
package gitutil
