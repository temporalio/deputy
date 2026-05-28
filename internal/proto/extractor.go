package proto

import (
	"strings"

	"github.com/google/osv-scalibr/extractor"

	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/purlx"
)

// ecosystemFromPURLType returns an OSV ecosystem name for PURL types that
// OSV-SCALIBR doesn't handle (returns empty string). This fills gaps for
// ecosystems like GitHub Actions that Deputy supports but SCALIBR doesn't.
func ecosystemFromPURLType(purlType string) string {
	switch purlType {
	case purlx.TypeGitHubActions:
		return "GitHub Actions"
	default:
		return ""
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

	isDirect := false
	if direct != nil && purl != nil {
		// Direct dependency matching varies by ecosystem:
		//
		// Go: Use module paths (with module root fallback for subpackages)
		// npm/Cargo/PyPI: Use package names directly
		//
		// The direct map contains:
		//   - Go: module paths with true (direct) or false (indirect)
		//   - npm: package names (e.g., "react", "@types/node")
		//   - Cargo: crate names (e.g., "tokio", "serde")
		//   - PyPI: normalized package names (e.g., "flask", "requests")
		switch purl.Type {
		case "golang":
			// Reconstruct module path from PURL namespace + name
			modulePath := pkg.Name
			if modulePath == "" {
				if purl.Namespace != "" {
					modulePath = purl.Namespace + "/" + purl.Name
				} else {
					modulePath = purl.Name
				}
			}
			// First check exact module path (handles submodules correctly)
			if val, exists := direct[modulePath]; exists {
				isDirect = val
			} else {
				// Fall back to module root for subpackage import paths
				moduleRoot := compare.GetModuleRoot(modulePath)
				isDirect = direct[moduleRoot]
			}
		case "npm":
			// npm: check package name (may include scope like @types/node)
			pkgName := purl.Name
			if purl.Namespace != "" {
				pkgName = "@" + purl.Namespace + "/" + purl.Name
			}
			isDirect = direct[pkgName]
		case "cargo":
			// Cargo: check crate name
			isDirect = direct[purl.Name]
		case "pypi":
			// PyPI: normalize and check package name (PEP 503: lowercase, _ for -)
			pkgName := normalizePyPIName(purl.Name)
			isDirect = direct[pkgName]
		case "docker", "oci":
			// Docker/OCI: base images from Dockerfile are always direct dependencies
			// They're explicitly declared in FROM instructions
			isDirect = true
		case "githubactions":
			// GitHub Actions: workflow uses are always direct dependencies
			// They're explicitly declared in workflow YAML files
			isDirect = true
		default:
			// Fall back to PURL string for unknown ecosystems
			isDirect = direct[purlStr]
		}
	}

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

		out[i] = &extractor.Package{
			Name:         pkg.Name,
			Version:      pkg.Version,
			Locations:    pkg.Locations,
			Licenses:     pkg.Licenses,
			LayerDetails: layerDetails,
			// Note: PURLType and other fields cannot be reliably reconstructed
			// from the proto representation. The Ecosystem() method won't work
			// on these reconstructed packages without PURLType.
		}

		if pkg.Direct && pkg.Purl != "" {
			direct[pkg.Purl] = true
		}
	}
	return out, direct
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
