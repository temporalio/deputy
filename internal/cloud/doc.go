// Package cloud provides cloud resource scanning capabilities for Deputy.
//
// # Architecture
//
// Cloud resource scanning follows Deputy's target provider pattern:
//
//  1. Target Resolution ([github.com/picatz/deputy/internal/targets/providers])
//     - Detects cloud URIs (aws://ami/..., azure://disk/..., gcp://image/...)
//     - Authenticates via SDK credential chains (never handles credentials directly)
//     - Downloads or streams resource data
//     - Provides fs.FS for inventory extraction
//
//  2. Resource Abstraction ([github.com/picatz/deputy/internal/cloud])
//     - Common interfaces for cloud resources across providers
//     - Smart downloading support (EBS Direct API downloads only needed blocks)
//     - Plugin protocol for custom cloud providers
//
//  3. Provider-Specific Packages
//     - [github.com/picatz/deputy/internal/cloud/aws] - AWS AMI, EBS, Lambda, ECR
//     - azure/ - Azure disks, ACR, Functions (future)
//     - gcp/ - GCP images, GAR, Functions (future)
//
//  4. Inventory Extraction ([github.com/picatz/deputy/internal/inventory])
//     - Uses OSV-SCALIBR to scan resource filesystem
//     - Same extractors as container/VM image scanning
//
//  5. Policy Evaluation ([github.com/picatz/deputy/internal/policy])
//     - Entrypoints: cloud_scan_report, cloud_scan_vulnerability
//     - Variables: resource.provider, resource.region, resource.tags
//
// # Supported Resources
//
// AWS:
//   - AMI (aws://ami/ami-xxx)
//   - EBS Snapshot (aws://ebs/snap-xxx)
//   - Lambda Function (aws://lambda/function-name)
//   - ECR Image (aws://ecr/repo:tag)
//
// Azure (future):
//   - VM Image (azure://image/subscription/rg/name)
//   - Managed Disk (azure://disk/subscription/rg/name)
//   - ACR Image (azure://acr/registry/repo:tag)
//   - Function (azure://function/subscription/rg/app/function)
//
// GCP (future):
//   - Compute Image (gcp://image/project/name)
//   - Persistent Disk (gcp://disk/project/zone/name)
//   - Artifact Registry Image (gcp://gar/region/project/repo/image:tag)
//   - Cloud Function (gcp://function/project/region/name)
//
// # Credential Handling
//
// Deputy never handles credentials directly. All authentication is delegated
// to standard SDK credential chains:
//   - AWS: Environment, shared credentials (~/.aws/credentials), IAM role
//   - Azure: DefaultAzureCredential (env, managed identity, CLI)
//   - GCP: Application Default Credentials
//
// # Plugin Extensibility
//
// Custom cloud providers (OpenStack, vSphere, etc.) can be added via plugins
// following the sandbox plugin pattern:
//   - Discovery: deputy-cloud-<name> executables in PATH
//   - Communication: ConnectRPC over Unix socket
//   - Protocol: CloudProviderService (api/deputy/cloud/v1/plugin.proto)
//
// # Data Flow
//
//	targets.Open("aws://ami/ami-xxx")
//	    └─ awsProvider.Open(...)
//	           ├─ aws.ResolveAMI(...) → EBS snapshot ID
//	           ├─ aws.OpenSnapshot(...) → io.ReaderAt (smart download)
//	           ├─ vmimage.ReadPartitions(...) → partition table
//	           └─ fsys.OpenFilesystem(...) → fs.FS
//	                  └─ inventory.ScanPackagesFS(...)
//	                         └─ []*extractor.Package
//	                                └─ vulnerability.Query(...)
package cloud
