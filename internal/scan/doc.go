// Package scan provides the core vulnerability scanning service for Deputy.
//
// This package orchestrates the end-to-end vulnerability scanning workflow:
// inventory collection, OSV vulnerability lookup, and result aggregation.
//
// # Architecture
//
// The scan package sits at the center of Deputy's analysis pipeline:
//
//	┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//	│  inventory  │────▶│    scan     │────▶│   report    │
//	│  (extract)  │     │  (analyze)  │     │  (render)   │
//	└─────────────┘     └─────────────┘     └─────────────┘
//	                          │
//	                          ▼
//	                    ┌─────────────┐
//	                    │ analysis/osv│
//	                    │  (lookup)   │
//	                    └─────────────┘
//
// # Service
//
// [Service] is the primary entry point for vulnerability scanning. It implements
// the [Scanner] interface and supports multiple scan targets:
//
//   - [Service.ScanRepository] - Git repositories (local or remote)
//   - [Service.ScanDirectory] - Local filesystem paths
//   - [Service.ScanSBOM] - Pre-extracted package lists
//   - [Service.ScanContainerImage] - Container images (remote, daemon, or tarball)
//   - [Service.ScanDockerfile] - Images referenced in Dockerfiles
//   - [Service.ScanPURL] - Individual package URLs
//
// Create a service with default configuration:
//
//	svc := scan.NewService()
//	result, err := svc.ScanDirectory(ctx, ".", scan.Options{})
//
// Or inject custom dependencies for testing:
//
//	svc := scan.NewServiceWithConfig(&scan.ServiceConfig{
//	    OSVClient:            mockClient,
//	    CollectInventory:     mockInventory,
//	    QueryVulnerabilities: mockQuery,
//	})
//
// # Results
//
// Scan operations return an [Execution] containing:
//
//   - [Result] - Findings and advisories (domain types from [vulnerability] package)
//   - Target metadata (repository, commit, image reference)
//   - Timing and diagnostic information
//
// The [Result] type contains:
//
//   - Findings: Per-package vulnerability matches with locations and affected imports
//   - Advisories: Deduplicated vulnerability metadata keyed by ID
//
// # Options
//
// [Options] configures scan behavior:
//
//   - Ecosystems: Filter to specific package ecosystems
//   - IgnoreUnfixed: Exclude vulnerabilities without fixes
//   - PublishedAfter/Before: Filter by advisory publication date
//   - LayerDetails: Include container layer information
//
// # Container Image Scanning
//
// Container image scanning extracts packages from image layers and tracks
// which layer introduced each package. This enables layer-aware policies
// that distinguish base image vulnerabilities from application dependencies.
//
// The [image.Info] type (from [internal/container/image]) captures image
// configuration, metadata, and build history for policy evaluation.
//
// # Data Flow
//
// A typical scan flows through these stages:
//
//  1. Target resolution - Determine scan type and materialize target
//  2. Inventory extraction - Parse manifests into [extractor.Package] list
//  3. Input conversion - Transform packages to [osv.PkgInput] for OSV API
//  4. Vulnerability lookup - Batch query OSV API via [osv.Client]
//  5. Result conversion - Transform OSV results to domain [vulnerability.Finding]
//  6. Result aggregation - Deduplicate advisories, merge findings
//
// # Thread Safety
//
// [Service] is safe for concurrent use. Each scan operation is independent
// and uses context for cancellation. The underlying [osv.Client] handles
// concurrent requests with rate limiting and deduplication.
//
// # Related Packages
//
//   - [internal/inventory] - Package extraction from manifests
//   - [internal/analysis/osv] - OSV API client and caching
//   - [internal/vulnerability] - Domain types (Finding, Advisory, Severity)
//   - [internal/report] - Result flattening and rendering
//   - [internal/policy] - CEL policy evaluation on scan results
package scan
