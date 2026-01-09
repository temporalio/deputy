// Package container provides container-related functionality for Deputy.
//
// # Architecture
//
// Container analysis in Deputy follows a layered architecture:
//
//  1. Target Resolution ([github.com/picatz/deputy/internal/targets/providers])
//     - Detects container image references (docker://, oci://, etc.)
//     - Opens images via go-containerregistry
//     - Provides [scalibrimage.Image] for inventory extraction
//
//  2. Image Configuration ([github.com/picatz/deputy/internal/container/image])
//     - Extracts configuration (USER, ENV, ENTRYPOINT, etc.)
//     - Extracts metadata (architecture, OS, layers, size)
//     - Provides security analysis helpers (IsRootUser, HasSensitiveEnv)
//
//  3. Inventory Extraction ([github.com/picatz/deputy/internal/inventory])
//     - Uses OSV-SCALIBR to scan image filesystem
//     - Detects packages from OS and language package managers
//     - Tracks which layer introduced each package
//
//  4. Vulnerability Analysis ([github.com/picatz/deputy/internal/scanning])
//     - Queries OSV database for package vulnerabilities
//     - Attaches layer details to findings for provenance
//
//  5. Policy Evaluation ([github.com/picatz/deputy/internal/policy])
//     - Evaluates CEL policies against image + vulnerabilities
//     - Variables: image, image_info, vulnerability.layerDetails
//
// # Subpackages
//
//   - [github.com/picatz/deputy/internal/container/image] - Image configuration and metadata
//
// # Data Flow
//
//	targets.Open("nginx:1.25")
//	    └─ ContainerImageData{V1Image, ...}
//	           ├─ image.Extract(v1Image) → image.Info
//	           │      └─ Config, Metadata, History
//	           └─ inventory.ScanPackagesContainerImage(...)
//	                  └─ []*extractor.Package (with layer info)
//	                         └─ inputs.Convert(...)
//	                                └─ []osv.PkgInput
//	                                       └─ osv.Query(...)
//	                                              └─ Finding + Advisory
package container
