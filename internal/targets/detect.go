package targets

import (
	"net/netip"
	"strings"
)

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

	// Docker Hub user/org images with tag (e.g., "temporalio/server:1.28.1", "library/nginx:1.25")
	// Pattern: exactly one slash, colon after the slash, tag looks like a version
	slashCount := strings.Count(target, "/")
	if slashCount == 1 && strings.Contains(target, ":") {
		parts := strings.SplitN(target, "/", 2)
		if len(parts) == 2 {
			// Check that the colon is after the slash (in the image:tag part)
			afterSlash := parts[1]
			if strings.Contains(afterSlash, ":") {
				tag := strings.SplitN(afterSlash, ":", 2)[1]
				// Container tags are typically versions or simple names
				// Git branches wouldn't typically be: refs/*, contain .., or be common version patterns
				if !strings.HasPrefix(tag, "refs/") && !strings.Contains(tag, "..") {
					// Additional heuristic: common version patterns
					// Most container tags start with v, a digit, or are common keywords
					if len(tag) > 0 && (tag[0] >= '0' && tag[0] <= '9' ||
						tag[0] == 'v' ||
						tag == "latest" ||
						tag == "stable" ||
						tag == "edge" ||
						tag == "dev" ||
						tag == "main" ||
						tag == "master" ||
						strings.HasPrefix(tag, "sha-") ||
						strings.Contains(tag, ".")) {
						return true
					}
				}
			}
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
//
// SECURITY: This function provides the first layer of SSRF protection by
// rejecting obviously local targets (paths, docker-daemon://, localhost, etc.)
// and known-bad IP patterns. However, it cannot protect against DNS rebinding
// attacks where an attacker-controlled hostname resolves to internal IPs.
//
// For complete SSRF protection, use network.SafeDialer which validates
// IP addresses AFTER DNS resolution, at connection time. This two-layer
// defense provides:
//
//  1. ValidateRemoteTarget: Fast rejection of known-bad inputs with helpful
//     error messages guiding users to correct alternatives.
//
//  2. network.SafeDialer: Connection-time validation that catches DNS
//     rebinding and other IP-based attacks.
//
// See internal/network/safedialer.go for the connection-time protection.
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

	// SSRF Protection: Extract host from target for IP/hostname checks
	// This handles schemes like oci://127.0.0.1/image, docker://10.0.0.1/app, etc.
	if err := validateTargetHost(target); err != nil {
		return err
	}

	return nil
}

// validateTargetHost extracts the host portion from various target formats
// and validates it against SSRF blocklists.
func validateTargetHost(target string) error {
	// Normalize: strip common schemes to extract host
	host := target
	for _, scheme := range []string{
		"oci://", "docker://", "container://",
		"https://", "http://",
		"git://", "ssh://",
	} {
		if strings.HasPrefix(strings.ToLower(host), scheme) {
			host = host[len(scheme):]
			break
		}
	}

	// Strip path/query: github.com/owner/repo -> github.com
	if idx := strings.IndexAny(host, "/?#"); idx != -1 {
		host = host[:idx]
	}

	// Strip port: registry.example.com:5000 -> registry.example.com
	// Handle IPv6 addresses in brackets: [::1]:5000 -> [::1]
	if strings.HasPrefix(host, "[") {
		// IPv6 in brackets
		if idx := strings.Index(host, "]:"); idx != -1 {
			host = host[:idx+1]
		}
	} else if idx := strings.LastIndex(host, ":"); idx != -1 {
		// IPv4 or hostname with port
		host = host[:idx]
	}

	// Strip user info: user@host -> host
	if idx := strings.Index(host, "@"); idx != -1 {
		host = host[idx+1:]
	}

	// Normalize IPv6: strip brackets for comparison
	hostForCheck := strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")

	// Block loopback addresses (SSRF protection)
	if isLoopbackHost(hostForCheck) {
		return &ValidationError{
			Target:     target,
			Reason:     "loopback addresses not accessible from remote server",
			Suggestion: "use a remote registry or git host",
		}
	}

	// Block cloud metadata endpoints (SSRF protection)
	if isMetadataEndpoint(hostForCheck) {
		return &ValidationError{
			Target:     target,
			Reason:     "metadata endpoints not allowed",
			Suggestion: "use a remote registry or git host",
		}
	}

	// Block private network ranges (SSRF protection)
	// Note: This is defense-in-depth; DNS rebinding attacks still possible
	if isPrivateNetwork(hostForCheck) {
		return &ValidationError{
			Target:     target,
			Reason:     "private network addresses not accessible from remote server",
			Suggestion: "use a public registry or git host",
		}
	}

	return nil
}

// isLoopbackHost checks if a host is a loopback address using net/netip.
func isLoopbackHost(host string) bool {
	host = strings.ToLower(host)

	// Hostname check
	if host == "localhost" {
		return true
	}

	// Try to parse as IP address
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false // Not an IP, can't be loopback
	}

	// net/netip handles all loopback variations (127.x.x.x, ::1, ::ffff:127.x.x.x)
	if addr.IsLoopback() {
		return true
	}

	// Also block unspecified (0.0.0.0, ::) - often used to bind to all interfaces
	if addr.IsUnspecified() {
		return true
	}

	return false
}

// isMetadataEndpoint checks if a host is a cloud metadata endpoint.
func isMetadataEndpoint(host string) bool {
	host = strings.ToLower(host)

	// Try to parse as IP address
	if addr, err := netip.ParseAddr(host); err == nil {
		// Link-local range (169.254.0.0/16) - used by cloud metadata services
		if addr.IsLinkLocalUnicast() {
			return true
		}
	}

	// Cloud provider metadata hostnames
	metadataHosts := []string{
		"metadata.google.internal",
		"metadata.goog",
		"metadata.azure.com",
		"management.azure.com",
		"instance-data", // AWS instance metadata
		"metadata",      // Generic metadata hostname
	}
	for _, mh := range metadataHosts {
		if host == mh || strings.HasSuffix(host, "."+mh) {
			return true
		}
	}

	return false
}

// isPrivateNetwork checks if a host is in private network ranges using net/netip.
func isPrivateNetwork(host string) bool {
	// Try to parse as IP address
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false // Not an IP, can't check ranges
	}

	// net/netip.IsPrivate() covers:
	// - 10.0.0.0/8
	// - 172.16.0.0/12
	// - 192.168.0.0/16
	// - fc00::/7 (IPv6 unique local)
	return addr.IsPrivate()
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
