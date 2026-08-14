package proto

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/opencontainers/go-digest"

	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/purlx"
)

// ecosystemFromPURLType returns an OSV ecosystem name for PURL types that
// OSV-SCALIBR doesn't handle (returns empty string). This fills gaps for
// ecosystems like GitHub Actions that Deputy supports but SCALIBR doesn't.
func ecosystemFromPURLType(purlType string) string {
	switch purlType {
	case purlx.TypeGitHubActions:
		return "GitHub Actions"
	case purlx.TypeMise:
		return "mise"
	case purlx.TypeAsdf:
		return "asdf"
	case "docker":
		// Dockerfile base images; matches the coverage report's vocabulary.
		return "docker"
	case "oci":
		return "oci"
	default:
		return ""
	}
}

// ExtractorPackageIsDirect reports whether pkg should be treated as a direct
// dependency using the same rules as ExtractorPackageToProto.
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
		return direct[purlx.NPMPackageName(purl.Namespace, purl.Name)]
	case "cargo":
		return direct[purl.Name]
	case "pypi":
		return direct[normalizePyPIName(purl.Name)]
	default:
		return direct[purl.String()]
	}
}

// ExtractorPackageToProto converts an OSV-SCALIBR extractor.Package to proto Package.
// The direct map indicates which packages are direct dependencies. For Go packages,
// the map keys are module roots (e.g., "github.com/google/osv-scalibr"). For other
// ecosystems, keys are PURL strings.
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
	if pkg.LayerMetadata != nil {
		layerDetails = &containerv1.LayerDetails{
			Index:       int32(pkg.LayerMetadata.Index),
			DiffId:      pkg.LayerMetadata.DiffID.String(),
			ChainId:     pkg.LayerMetadata.ChainID.String(),
			Command:     pkg.LayerMetadata.Command,
			InBaseImage: pkg.LayerMetadata.BaseImageIndex > 0,
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
		Locations:    dependency.PackagePaths(pkg),
		Licenses:     pkg.Licenses,
		LayerDetails: layerDetails,
	}
}

// ExtractorPackagesToProto converts a slice of OSV-SCALIBR packages to proto Packages.
// The direct map indicates which packages are direct dependencies. For Go packages,
// the map keys are module roots (e.g., "github.com/google/osv-scalibr"). For other
// ecosystems, keys are PURL strings.
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

		// SCALIBR records base image membership as an index into the image's base
		// image matches rather than a boolean, and the proto only carries the
		// boolean, so a member round-trips to index 1: "matched some base image".
		var layerMetadata *extractor.LayerMetadata
		if pkg.LayerDetails != nil {
			baseImageIndex := 0
			if pkg.LayerDetails.InBaseImage {
				baseImageIndex = 1
			}
			layerMetadata = &extractor.LayerMetadata{
				Index:          int(pkg.LayerDetails.Index),
				DiffID:         digest.Digest(pkg.LayerDetails.DiffId),
				ChainID:        digest.Digest(pkg.LayerDetails.ChainId),
				Command:        pkg.LayerDetails.Command,
				BaseImageIndex: baseImageIndex,
			}
		}

		purlType := ""
		if pkg.Purl != "" {
			if parsed, err := purlx.ParseLoose(pkg.Purl); err == nil {
				purlType = parsed.Type
			}
		}

		out[i] = &extractor.Package{
			Name:          pkg.Name,
			Version:       pkg.Version,
			PURLType:      purlType,
			Licenses:      pkg.Licenses,
			LayerMetadata: layerMetadata,
			// Note: PURL metadata and other fields cannot be reliably reconstructed
			// from the proto representation. Type-specific PURL formatting may still
			// be lossy for ecosystems whose identity depends on metadata.
		}
		dependency.SetPackagePaths(out[i], pkg.Locations)

		recordProtoPackageDirectness(direct, pkg)
	}
	return out, direct
}

func recordProtoPackageDirectness(direct map[string]bool, pkg *dependencyv1.Package) {
	if pkg == nil {
		return
	}
	isDirect := pkg.Direct

	recordDirectKey(direct, pkg.Purl, isDirect)
	recordDirectKey(direct, pkg.Name, isDirect)

	parsed, err := purlx.ParseLoose(pkg.Purl)
	if err != nil {
		return
	}
	recordDirectKey(direct, parsed.String(), isDirect)

	packageName := parsed.Name
	if parsed.Namespace != "" {
		packageName = parsed.Namespace + "/" + parsed.Name
	}

	switch parsed.Type {
	case "golang":
		if packageName != "" {
			recordDirectKey(direct, packageName, isDirect)
			if isDirect {
				recordDirectKey(direct, compare.GetModuleRoot(packageName), true)
			}
		}
	case "npm":
		recordDirectKey(direct, purlx.NPMPackageName(parsed.Namespace, parsed.Name), isDirect)
	case "cargo":
		recordDirectKey(direct, parsed.Name, isDirect)
	case "pypi":
		recordDirectKey(direct, normalizePyPIName(parsed.Name), isDirect)
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

// normalizePyPIName normalizes a PyPI package name per PEP 503:
// lowercase and replace all runs of [-_.] with a single underscore.
// This ensures consistent matching between manifest files and PURLs.
func normalizePyPIName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	return name
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
			Name:     "stdlib",
			Version:  bestStdlibVersion,
			PURLType: "golang",
			Location: bestStdlib.Location,
			Licenses: bestStdlib.Licenses,
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
