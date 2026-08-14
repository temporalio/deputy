package proto

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"

	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/purlx"
)

// ecosystemFromPURLType returns the ecosystem display name for PURL types that
// OSV-SCALIBR doesn't handle (returns empty string). This fills gaps for
// ecosystems like GitHub Actions that Deputy supports but SCALIBR doesn't.
// The names come from the ecosystem registry rather than literals here, so the
// spelling this emits is the one every other surface resolves.
func ecosystemFromPURLType(purlType string) string {
	var eco ecosystem.Ecosystem
	switch purlType {
	case purlx.TypeGitHubActions:
		eco = ecosystem.GitHubActions
	case purlx.TypeMise:
		eco = ecosystem.Mise
	case purlx.TypeAsdf:
		eco = ecosystem.Asdf
	case "docker":
		// Dockerfile base images; matches the coverage report's vocabulary.
		eco = ecosystem.Docker
	case "oci":
		eco = ecosystem.OCI
	default:
		return ""
	}
	return ecosystem.Display(eco)
}

// ExtractorPackageIsDirect reports whether pkg should be treated as a direct
// dependency using the same rules as ExtractorPackageToProto.
//
// The key it builds from the scanned package comes from
// [ecosystem.Ecosystem.NameEquivalenceKey], the same call
// compare.CollectDirectDependenciesFromWorkspace makes when it reads the
// manifest. Both sides run one rule, so a Cargo crate a manifest spells
// "serde-json" and a lockfile spells "serde_json" is one key, not two. The key
// decides the lookup only; the package keeps the name it reported.
//
// npm resolves by name and version through [compare.LookupDirect], because a
// declaration there names a range and a lockfile can hold several copies of the
// name it resolves to. Cargo can hold several versions of one crate too, and its
// lookup is still name-only, so a crate the manifest declares marks every copy of
// that name direct. Resolving it needs Cargo.lock read against the root crate's
// requirement, which no parser here does yet.
func ExtractorPackageIsDirect(pkg *extractor.Package, direct map[string]bool) bool {
	if pkg == nil {
		return false
	}
	purl := pkg.PURL()
	if purl == nil {
		return false
	}

	switch {
	case purl.Type == "docker" || purl.Type == "oci":
		// Docker/OCI: base images from Dockerfile are always direct dependencies.
		return true
	case purlx.IsGitHubActionsType(purl.Type):
		// GitHub Actions: workflow uses are always direct dependencies.
		return true
	case purl.Type == purlx.TypeMise || purl.Type == purlx.TypeAsdf:
		// mise/asdf: every tool is explicitly declared in config.
		return true
	}

	if direct == nil {
		return false
	}

	switch purl.Type {
	case "golang":
		// Reconstruct module path from PURL namespace + name.
		modulePath := pkg.Name
		if modulePath == "" {
			if purl.Namespace != "" {
				modulePath = purl.Namespace + "/" + purl.Name
			} else {
				modulePath = purl.Name
			}
		}
		// First check exact module path (handles submodules correctly), then
		// fall back to module root for subpackage import paths.
		if val, exists := direct[modulePath]; exists {
			return val
		}
		moduleRoot := compare.GetModuleRoot(modulePath)
		return direct[moduleRoot]
	case "npm":
		// npm: check package name (may include scope like @types/node).
		pkgName := purl.Name
		if purl.Namespace != "" {
			pkgName = "@" + purl.Namespace + "/" + purl.Name
		}
		// The version matters here, because one npm lockfile routinely carries
		// two copies of a declared name and only one of them is the copy the
		// declaration resolved to. See [compare.LookupDirect].
		return compare.LookupDirect(direct, pkgName, pkg.Version)
	case "cargo":
		return direct[ecosystem.Cargo.NameEquivalenceKey(purl.Name)]
	case "pypi":
		return direct[ecosystem.PyPI.NameEquivalenceKey(purl.Name)]
	default:
		return direct[purl.String()]
	}
}

// ExtractorPackageToProto converts an OSV-SCALIBR extractor.Package to proto Package.
// The direct map indicates which packages are direct dependencies, keyed by the
// name a package goes by in its own ecosystem: a module root for Go (e.g.
// "github.com/google/osv-scalibr"), a scoped package name for npm, a crate name
// for Cargo, and a normalized distribution name for PyPI. Ecosystems with no
// rule of their own are keyed by PURL string. ExtractorPackageIsDirect builds
// the key, and compare.CollectDirectDependenciesFromWorkspace produces the map.
func ExtractorPackageToProto(pkg *extractor.Package, direct map[string]bool) *dependencyv1.Package {
	if pkg == nil {
		return nil
	}

	purl := pkg.PURL()
	purlStr := ""
	if purl != nil {
		purlStr = purl.String()
	}

	isDirect := ExtractorPackageIsDirect(pkg, direct)

	var layerDetails *containerv1.LayerDetails
	if pkg.LayerDetails != nil {
		layerDetails = &containerv1.LayerDetails{
			Index:       int32(pkg.LayerDetails.Index),
			DiffId:      pkg.LayerDetails.DiffID,
			ChainId:     pkg.LayerDetails.ChainID,
			Command:     pkg.LayerDetails.Command,
			InBaseImage: pkg.LayerDetails.InBaseImage,
		}
	}

	// Get ecosystem from SCALIBR, falling back to our custom mapping for
	// PURL types SCALIBR doesn't recognize (e.g., GitHub Actions)
	ecosystem := pkg.Ecosystem().String()
	if ecosystem == "" && purl != nil {
		ecosystem = ecosystemFromPURLType(purl.Type)
	}

	return &dependencyv1.Package{
		Name:         pkg.Name,
		Ecosystem:    ecosystem,
		Version:      pkg.Version,
		Purl:         purlStr,
		Direct:       isDirect,
		Locations:    pkg.Locations,
		Licenses:     pkg.Licenses,
		LayerDetails: layerDetails,
	}
}

// ExtractorPackagesToProto converts a slice of OSV-SCALIBR packages to proto Packages.
// The direct map indicates which packages are direct dependencies. For Go packages,
// the map keys are module roots (e.g., "github.com/google/osv-scalibr"). For other
// ecosystems, keys are PURL strings.
//
// A package of an ecosystem no collector reads converts to is_direct = false,
// which the output contract cannot tell from a package declared transitive. That
// limit is real and reported nowhere; see issue #246, which moves it into the
// contract instead of leaving a caller to infer it.
func ExtractorPackagesToProto(pkgs []*extractor.Package, direct map[string]bool) []*dependencyv1.Package {
	if len(pkgs) == 0 {
		return nil
	}
	out := make([]*dependencyv1.Package, len(pkgs))
	for i, pkg := range pkgs {
		out[i] = ExtractorPackageToProto(pkg, direct)
	}
	return out
}

// ExtractorPackagesFromProto converts proto Packages back to a simplified representation.
// Note: This is a lossy conversion as extractor.Package contains fields that aren't
// stored in the proto (e.g., Metadata, SourceCode, Plugins). This is primarily useful
// for testing or when you only need the basic package identity fields.
//
// For full fidelity, store the original extractor.Package or re-extract from source.
func ExtractorPackagesFromProto(pkgs []*dependencyv1.Package) ([]*extractor.Package, map[string]bool) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	out := make([]*extractor.Package, len(pkgs))
	direct := make(map[string]bool)

	for i, pkg := range pkgs {
		if pkg == nil {
			continue
		}

		var layerDetails *extractor.LayerDetails
		if pkg.LayerDetails != nil {
			layerDetails = &extractor.LayerDetails{
				Index:       int(pkg.LayerDetails.Index),
				DiffID:      pkg.LayerDetails.DiffId,
				ChainID:     pkg.LayerDetails.ChainId,
				Command:     pkg.LayerDetails.Command,
				InBaseImage: pkg.LayerDetails.InBaseImage,
			}
		}

		purlType := ""
		if pkg.Purl != "" {
			if parsed, err := purlx.ParseLoose(pkg.Purl); err == nil {
				purlType = parsed.Type
			}
		}

		out[i] = &extractor.Package{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Locations:    pkg.Locations,
			PURLType:     purlType,
			Licenses:     pkg.Licenses,
			LayerDetails: layerDetails,
			// Note: PURL metadata and other fields cannot be reliably reconstructed
			// from the proto representation. Type-specific PURL formatting may still
			// be lossy for ecosystems whose identity depends on metadata.
		}

		recordProtoPackageDirectness(direct, pkg)
	}
	return out, direct
}

// recordProtoPackageDirectness records every key a package's directness can be
// looked up under when the reconstructed extractor.Package is converted back.
// [ExtractorPackageIsDirect] performs that lookup, so the ecosystem-specific
// keys built here are the ones it builds: an equivalence key for Cargo and
// PyPI, whose two spellings of a name have to meet on one key, and the reported
// name elsewhere.
func recordProtoPackageDirectness(direct map[string]bool, pkg *dependencyv1.Package) {
	if pkg == nil {
		return
	}
	isDirect := pkg.Direct

	recordDirectKey(direct, pkg.Purl, isDirect)

	parsed, err := purlx.ParseLoose(pkg.Purl)
	if err != nil {
		recordDirectKey(direct, pkg.Name, isDirect)
		return
	}
	recordDirectKey(direct, parsed.String(), isDirect)

	packageName := parsed.Name
	if parsed.Namespace != "" {
		packageName = parsed.Namespace + "/" + parsed.Name
	}

	// An npm package carries its own version here, so its versioned key is the
	// whole answer and no bare name is recorded beside it: a bare name is the key
	// that answers for every copy of the name, which is exactly what a decoded
	// response must not do once the versions are known. Every other ecosystem is
	// keyed by name, so the name key is recorded for them as before.
	if parsed.Type == "npm" && pkg.Version != "" {
		npmName := parsed.Name
		if parsed.Namespace != "" {
			npmName = "@" + parsed.Namespace + "/" + parsed.Name
		}
		recordDirectKey(direct, compare.DirectVersionKey(npmName, pkg.Version), isDirect)
		return
	}
	recordDirectKey(direct, pkg.Name, isDirect)

	switch parsed.Type {
	case "golang":
		if packageName != "" {
			recordDirectKey(direct, packageName, isDirect)
			if isDirect {
				recordDirectKey(direct, compare.GetModuleRoot(packageName), true)
			}
		}
	case "npm":
		npmName := parsed.Name
		if parsed.Namespace != "" {
			npmName = "@" + parsed.Namespace + "/" + parsed.Name
		}
		recordDirectKey(direct, npmName, isDirect)
	case "cargo":
		recordDirectKey(direct, ecosystem.Cargo.NameEquivalenceKey(parsed.Name), isDirect)
	case "pypi":
		recordDirectKey(direct, ecosystem.PyPI.NameEquivalenceKey(parsed.Name), isDirect)
	default:
		recordDirectKey(direct, packageName, isDirect)
	}
}

func recordDirectKey(direct map[string]bool, key string, isDirect bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	if direct[key] {
		return
	}
	direct[key] = isDirect
}

// FilterOptions configures which packages to exclude from output.
type FilterOptions struct {
	// ExcludeMainModules is a set of Go module paths that represent the project
	// being analyzed. Packages matching these modules are excluded from output
	// to avoid showing the project as its own dependency.
	ExcludeMainModules map[string]bool

	// DeduplicateStdlib removes duplicate Go stdlib entries (go vs stdlib,
	// multiple versions) keeping only a single "stdlib" entry with the highest
	// version found.
	DeduplicateStdlib bool
}

// FilterPackages applies filtering rules to exclude unwanted packages from output.
// This filters out:
//   - Main modules (the project itself appearing as a dependency)
//   - Duplicate Go stdlib entries (go vs stdlib, multiple versions)
//
// The original slice is not modified; a new filtered slice is returned.
func FilterPackages(pkgs []*extractor.Package, opts FilterOptions) []*extractor.Package {
	if len(pkgs) == 0 {
		return pkgs
	}

	// Track best stdlib entry for deduplication
	var bestStdlib *extractor.Package
	bestStdlibVersion := ""

	out := make([]*extractor.Package, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}

		purl := pkg.PURL()
		if purl == nil {
			out = append(out, pkg)
			continue
		}

		// Handle Go packages
		if purl.Type == "golang" {
			modulePath := pkg.Name
			if modulePath == "" {
				if purl.Namespace != "" {
					modulePath = purl.Namespace + "/" + purl.Name
				} else {
					modulePath = purl.Name
				}
			}

			// Skip relative path replace directives (e.g., "../..", "./local").
			// These are local development artifacts from go.mod replace directives
			// pointing to filesystem paths, not actual module dependencies.
			if compare.IsRelativePathModule(modulePath) {
				continue
			}

			// Check if this is a main module (self-reference)
			if len(opts.ExcludeMainModules) > 0 {
				if opts.ExcludeMainModules[modulePath] {
					continue // Skip self-reference
				}
				// Also check module root for nested modules
				moduleRoot := compare.GetModuleRoot(modulePath)
				if moduleRoot != modulePath && opts.ExcludeMainModules[moduleRoot] {
					continue // Skip self-reference
				}
			}

			// Handle stdlib deduplication: "go" and "stdlib" are both pseudo-packages
			// representing the Go runtime. Keep only one, preferring "stdlib" naming
			// and the highest version found.
			if opts.DeduplicateStdlib {
				name := purl.Name
				if name == "go" || name == "stdlib" {
					// Compare versions to keep the best one
					if bestStdlib == nil || compareStdlibEntry(pkg, bestStdlib) > 0 {
						bestStdlib = pkg
						bestStdlibVersion = pkg.Version
					}
					continue // Don't add yet, will add best one at the end
				}
			}
		}

		out = append(out, pkg)
	}

	// Add the best stdlib entry if we're deduplicating
	if opts.DeduplicateStdlib && bestStdlib != nil {
		// Normalize to "stdlib" name for consistency
		stdlibPkg := &extractor.Package{
			Name:      "stdlib",
			Version:   bestStdlibVersion,
			PURLType:  "golang",
			Locations: bestStdlib.Locations,
			Licenses:  bestStdlib.Licenses,
		}
		out = append(out, stdlibPkg)
	}

	return out
}

// compareStdlibEntry compares two stdlib package entries.
// Returns > 0 if a is "better" than b (prefer "stdlib" name, then higher version).
func compareStdlibEntry(a, b *extractor.Package) int {
	aPURL := a.PURL()
	bPURL := b.PURL()

	// Prefer "stdlib" name over "go"
	aIsStdlib := aPURL != nil && aPURL.Name == "stdlib"
	bIsStdlib := bPURL != nil && bPURL.Name == "stdlib"
	if aIsStdlib && !bIsStdlib {
		return 1
	}
	if bIsStdlib && !aIsStdlib {
		return -1
	}

	// Compare versions - higher is better
	return strings.Compare(a.Version, b.Version)
}
