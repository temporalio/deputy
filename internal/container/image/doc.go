// Package image provides container image configuration and metadata types.
//
// This package contains domain types for representing container image configuration
// (USER, ENV, ENTRYPOINT, etc.) and metadata (architecture, OS, layers) extracted
// from OCI/Docker images. These types are used for policy evaluation and security
// analysis across Deputy's scan, SBOM, and proxy commands.
//
// # Types
//
// The primary types are:
//   - [Config] - Image configuration (Dockerfile runtime settings)
//   - [Metadata] - Image metadata (architecture, size, layers)
//   - [Info] - Combined configuration, metadata, and build history
//   - [Ref] - Image reference/provenance (registry, repository, tag, digest)
//   - [PolicyPayload] - Complete image data for policy evaluation
//
// # Extracting Image Information
//
// Use [Extract] to get configuration and metadata from a container image:
//
//	info, err := image.Extract(v1Image)
//	if err != nil {
//	    return err
//	}
//	if info.Config.IsRootUser() {
//	    // warn about running as root
//	}
//
// # Image References
//
// The [Ref] type represents image provenance:
//
//	ref := &image.Ref{
//	    Registry:   "docker.io",
//	    Repository: "library/nginx",
//	    Tag:        "1.25",
//	}
//	fmt.Println(ref.String())  // "docker.io/library/nginx:1.25"
//
// Create from scan target provenance:
//
//	ref := image.RefFromProvenance(target.Provenance)
//
// # Policy Integration
//
// The [Info.ToMap] and [PolicyPayload.ToMap] methods convert image data to maps
// suitable for CEL policy evaluation:
//
//	payload := &image.PolicyPayload{Ref: ref, Info: info}
//	celVars["image"] = payload.ToMap()
//
// This provides access to fields like `image.config.is_root`,
// `image.metadata.layer_count`, and `image.registry` in policies.
//
// # Security Analysis
//
// Helper methods support security analysis:
//
//	if config.IsRootUser() {
//	    // Image runs as root (security concern)
//	}
//	if vars := config.HasSensitiveEnv(); len(vars) > 0 {
//	    // Found potential secrets in environment variables
//	}
package image
