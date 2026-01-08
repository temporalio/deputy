package targets

import "strings"

// DetectKind determines the target type from a target string.
// Returns empty string if the type cannot be determined, in which case
// callers should fall back to repository/directory scanning.
//
// This function implements shared detection logic used by both the
// in-process client and remote server. It does NOT perform security
// validation - that is the caller's responsibility.
func DetectKind(target string) Kind {
	// PURL detection (pkg:ecosystem/name@version)
	if strings.HasPrefix(target, "pkg:") {
		return KindPURL
	}

	// Container image URI schemes
	if strings.HasPrefix(target, "docker://") ||
		strings.HasPrefix(target, "oci://") ||
		strings.HasPrefix(target, "docker-daemon://") ||
		strings.HasPrefix(target, "tarball://") ||
		strings.HasPrefix(target, "oci-archive://") ||
		strings.HasPrefix(target, "oci-layout://") {
		return KindContainerImage
	}

	// Container registry patterns
	if LooksLikeContainerRef(target) {
		return KindContainerImage
	}

	// Stdin SBOM indicator
	if target == "-" {
		return KindSBOM
	}

	// File extension heuristics for SBOM files
	if strings.HasSuffix(target, ".json") ||
		strings.HasSuffix(target, ".spdx") ||
		strings.HasSuffix(target, ".cdx") ||
		strings.HasSuffix(target, ".sbom") {
		return KindSBOM
	}

	// Dockerfile detection
	if strings.HasSuffix(target, "Dockerfile") ||
		strings.Contains(target, "Dockerfile.") ||
		strings.HasSuffix(target, ".dockerfile") {
		return KindDockerfile
	}

	// Default: unknown (caller decides, typically KindGit or KindDir)
	return KindUnspecified
}

// LooksLikeContainerRef checks if target looks like a container image reference.
// This includes both well-known registries and common patterns.
func LooksLikeContainerRef(target string) bool {
	// Skip if it looks like a local path
	if strings.HasPrefix(target, "/") ||
		strings.HasPrefix(target, "./") ||
		strings.HasPrefix(target, "../") ||
		strings.HasPrefix(target, "~/") ||
		target == "." {
		return false
	}

	// Well-known container registries
	knownRegistries := []string{
		"ghcr.io/",
		"gcr.io/",
		"quay.io/",
		"docker.io/",
		"registry.gitlab.com/",
		"mcr.microsoft.com/",
		"public.ecr.aws/",
	}
	for _, r := range knownRegistries {
		if strings.HasPrefix(target, r) {
			return true
		}
	}

	// AWS ECR pattern: 123456789012.dkr.ecr.us-east-1.amazonaws.com/repo
	if strings.Contains(target, ".dkr.ecr.") && strings.Contains(target, ".amazonaws.com") {
		return true
	}

	// Azure ACR pattern: myregistry.azurecr.io/repo
	parts := strings.Split(target, "/")
	if len(parts) > 0 && strings.HasSuffix(parts[0], ".azurecr.io") {
		return true
	}

	// Google Artifact Registry: us-docker.pkg.dev/project/repo/image
	if strings.Contains(target, ".pkg.dev/") {
		return true
	}

	// Localhost registry (for local development)
	if strings.HasPrefix(target, "localhost:") || strings.HasPrefix(target, "localhost/") {
		return true
	}

	// Docker Hub library images with tag (e.g., "nginx:1.25", "alpine:3.19")
	// Must have a colon but no slash (to avoid matching git refs like "owner/repo:branch")
	if !strings.Contains(target, "/") && strings.Contains(target, ":") {
		// Exclude git-like patterns (could be branch refs)
		tag := strings.SplitN(target, ":", 2)[1]
		// Container tags typically don't have these patterns
		if !strings.HasPrefix(tag, "refs/") && !strings.Contains(tag, "..") {
			return true
		}
	}

	return false
}

// IsLocalTarget returns true if the target refers to a local resource
// that cannot be accessed by a remote server.
func IsLocalTarget(target string) bool {
	// Stdin
	if target == "-" {
		return true
	}

	// Filesystem paths
	if strings.HasPrefix(target, "/") ||
		strings.HasPrefix(target, "./") ||
		strings.HasPrefix(target, "../") ||
		strings.HasPrefix(target, "~/") ||
		target == "." {
		return true
	}

	// Local-only container transports
	if strings.HasPrefix(target, "docker-daemon://") ||
		strings.HasPrefix(target, "tarball://") ||
		strings.HasPrefix(target, "oci-archive://") ||
		strings.HasPrefix(target, "oci-layout://") {
		return true
	}

	// Localhost registry
	if strings.HasPrefix(target, "localhost:") || strings.HasPrefix(target, "localhost/") {
		return true
	}

	return false
}

// ValidateRemoteTarget checks if a target can be used with a remote server.
// Returns an error with a helpful message if the target is local-only.
func ValidateRemoteTarget(target string) error {
	if target == "" {
		return &ValidationError{Target: target, Reason: "target is required"}
	}

	if target == "-" {
		return &ValidationError{
			Target:      target,
			Reason:      "stdin target (-) not supported for remote server",
			Suggestion:  "upload SBOM bytes using DiffSBOM instead",
		}
	}

	if strings.HasPrefix(target, "/") {
		return &ValidationError{
			Target:     target,
			Reason:     "absolute paths not supported for remote server",
			Suggestion: "use git URL or container reference",
		}
	}

	if strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") {
		return &ValidationError{
			Target:     target,
			Reason:     "relative paths not supported for remote server",
			Suggestion: "use git URL or container reference",
		}
	}

	if strings.HasPrefix(target, "~/") {
		return &ValidationError{
			Target:     target,
			Reason:     "home directory paths not supported for remote server",
			Suggestion: "use git URL or container reference",
		}
	}

	if target == "." {
		return &ValidationError{
			Target:     target,
			Reason:     "current directory (.) not supported for remote server",
			Suggestion: "use git URL or container reference",
		}
	}

	if strings.HasPrefix(target, "docker-daemon://") {
		return &ValidationError{
			Target:     target,
			Reason:     "docker-daemon:// not supported for remote server",
			Suggestion: "use remote registry reference",
		}
	}

	if strings.HasPrefix(target, "tarball://") {
		return &ValidationError{
			Target:     target,
			Reason:     "tarball:// not supported for remote server",
			Suggestion: "use remote registry reference",
		}
	}

	if strings.HasPrefix(target, "oci-archive://") {
		return &ValidationError{
			Target:     target,
			Reason:     "oci-archive:// not supported for remote server",
			Suggestion: "use remote registry reference",
		}
	}

	if strings.HasPrefix(target, "oci-layout://") {
		return &ValidationError{
			Target:     target,
			Reason:     "oci-layout:// not supported for remote server",
			Suggestion: "use remote registry reference",
		}
	}

	if strings.HasPrefix(target, "localhost:") || strings.HasPrefix(target, "localhost/") {
		return &ValidationError{
			Target:     target,
			Reason:     "localhost registry not accessible from remote server",
			Suggestion: "push to a remote registry first",
		}
	}

	return nil
}

// ValidationError provides detailed information about why a target is invalid.
type ValidationError struct {
	Target     string
	Reason     string
	Suggestion string
}

func (e *ValidationError) Error() string {
	if e.Suggestion != "" {
		return e.Reason + "; " + e.Suggestion
	}
	return e.Reason
}
