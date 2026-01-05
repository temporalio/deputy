package scan

import (
	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/analysis/osv"
	"github.com/picatz/deputy/internal/scan/inputs"
)

// Type aliases for cleaner scan package API.
type (
	ManifestResolver          = inputs.Resolver
	ManifestResolverFunc      = inputs.ResolverFunc
	GitManifestResolver       = inputs.GitResolver
	WorkspaceManifestResolver = inputs.WorkspaceResolver
	PackageInputOptions       = inputs.Options
)

// NewGitManifestResolver creates a resolver for a specific git commit.
var NewGitManifestResolver = inputs.NewGitResolver

// NewWorkspaceManifestResolver creates a resolver for a workspace filesystem.
var NewWorkspaceManifestResolver = inputs.NewWorkspaceResolver

// PackagesToInputs converts packages to OSV query inputs.
func PackagesToInputs(pkgs []*extractor.Package, opts PackageInputOptions) []osv.PkgInput {
	return inputs.Convert(pkgs, opts)
}

// BuildPackageDirectMap creates a map of direct dependencies.
func BuildPackageDirectMap(ins []osv.PkgInput) map[string]bool {
	return inputs.BuildDirectMap(ins)
}

// MergeDirectMaps combines multiple direct dependency maps.
func MergeDirectMaps(maps ...map[string]bool) map[string]bool {
	return inputs.MergeDirectMaps(maps...)
}

// BuildPackageSources creates a map of package sources.
func BuildPackageSources(ins []osv.PkgInput) map[string][]string {
	return inputs.BuildSourcesMap(ins)
}
