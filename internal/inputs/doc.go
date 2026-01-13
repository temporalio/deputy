// Package inputs provides utilities for converting extracted packages into
// OSV query inputs with manifest metadata enrichment.
//
// The main entry point is [Convert], which transforms SCALIBR packages into
// [osv.PkgInput] records with:
//   - Normalized ecosystem names
//   - Direct dependency detection
//   - Manifest reference grouping (dependencies, devDependencies, etc.)
//   - Container image layer details preservation
//
// # Manifest Resolution
//
// The [Resolver] interface abstracts file access for manifest parsing:
//
//	type Resolver interface {
//	    ReadFile(path string) ([]byte, error)
//	}
//
// Two implementations are provided:
//   - [GitResolver] - reads from a specific git commit
//   - [WorkspaceResolver] - reads from a workspace filesystem
//
// # Supported Ecosystems
//
// Manifest parsing supports dependency group detection for:
//   - Go (go.mod) - direct via require statements
//   - npm/yarn/pnpm (package.json) - dependencies, devDependencies, etc.
//   - Cargo (Cargo.toml) - dependencies, dev-dependencies, build-dependencies
//   - uv (uv.lock) - dependencies with optional/dev groups
//   - GitHub Actions - workflow and action manifest detection
package inputs
