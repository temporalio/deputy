package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/spf13/cobra"
)

// scanImageSchemes are the URL schemes that indicate container image targets.
// These schemes are handled by the container image provider.
var scanImageSchemes = map[string]struct{}{
	"docker":        {}, // Remote registry (docker://ghcr.io/owner/repo:tag)
	"oci":           {}, // Remote registry (oci://ghcr.io/owner/repo:tag)
	"container":     {}, // Remote registry (container://nginx:1.25)
	"docker-daemon": {}, // Local Docker daemon (docker-daemon://myapp:latest)
	"tarball":       {}, // Docker save tarball (tarball:///path/to/image.tar)
	"oci-archive":   {}, // OCI archive tarball (oci-archive:///path/to/oci.tar)
	"oci-layout":    {}, // OCI layout directory (oci-layout:///path/to/layout)
}

// knownGitHosts are hostnames that should be treated as Git repositories, not container registries.
// This helps disambiguate targets like "github.com/owner/repo" from "owner/repo:tag".
var knownGitHosts = map[string]struct{}{
	"github.com":    {},
	"gitlab.com":    {},
	"bitbucket.org": {},
}

// isPURLTarget returns true if the target is a Package URL (pkg:ecosystem/name@version).
func isPURLTarget(target string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(target)), "pkg:")
}

// isImageTargetScheme returns true if the target has an explicit container image scheme.
func isImageTargetScheme(target string) bool {
	scheme, _, ok := strings.Cut(strings.TrimSpace(target), "://")
	if !ok {
		return false
	}
	_, ok = scanImageSchemes[strings.ToLower(scheme)]
	return ok
}

// looksLikeContainerReference returns true if the target appears to be a container image reference
// without an explicit scheme. This uses heuristics to distinguish container references from
// Git repository paths.
//
// Detection rules (in order):
//  1. Explicit schemes (://): false - these are handled separately
//  2. PURLs (pkg:): false - Package URLs are not images
//  3. Relative/absolute paths (. or /): false - likely local paths
//  4. Git SSH URLs (git@ or ssh://): false - Git repositories
//  5. Git URLs (.git suffix): false - Git repositories
//  6. Whitespace: false - invalid reference
//  7. Invalid Docker reference: false - must parse as Docker ref
//  8. Email-like @ before /: false - likely email or SSH URL
//
// After these exclusions, we check the host:
//   - No host (e.g., "alpine"): true - Docker Hub library image
//   - Known Git host (github.com, etc.): false - Git repository
//   - Has dot or colon in host: true - explicit registry or port
//   - Otherwise: require explicit tag/digest to disambiguate from "owner/repo"
//
// Examples:
//   - "alpine:3.19" -> true (Docker Hub library image with tag)
//   - "alpine" -> true (Docker Hub library image, implies :latest)
//   - "nginx" -> true (Docker Hub library image)
//   - "owner/repo:v1.0" -> true (has explicit tag)
//   - "owner/repo@sha256:..." -> true (has explicit digest)
//   - "owner/repo" -> false (ambiguous, could be GitHub repo)
//   - "github.com/owner/repo" -> false (known Git host)
//   - "ghcr.io/owner/repo:v1" -> true (registry with dot in host)
//   - "localhost:5000/app:dev" -> true (localhost with port)
func looksLikeContainerReference(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	// Explicit schemes are handled by isImageTargetScheme
	if strings.Contains(target, "://") {
		return false
	}
	// PURLs are not container references
	if strings.HasPrefix(strings.ToLower(target), "pkg:") {
		return false
	}
	// Local paths are not container references
	if strings.HasPrefix(target, ".") || strings.HasPrefix(target, "/") {
		return false
	}
	// Git SSH URLs are not container references
	if strings.HasPrefix(target, "git@") || strings.HasPrefix(target, "ssh://") {
		return false
	}
	// Git URLs are not container references
	if strings.HasSuffix(target, ".git") {
		return false
	}
	// Whitespace in reference is invalid
	if strings.ContainsAny(target, " \t\n") {
		return false
	}
	// Must parse as a valid Docker reference
	if _, err := name.ParseReference(target, name.WeakValidation); err != nil {
		return false
	}
	// Email-like patterns (@ before /) are not container references
	if at := strings.Index(target, "@"); at != -1 {
		if slash := strings.Index(target, "/"); slash == -1 || at < slash {
			return false
		}
	}

	// Check the host portion to disambiguate
	host := imageHost(target)
	if host == "" {
		// No host = Docker Hub library image (e.g., "alpine", "nginx")
		return true
	}
	host = strings.ToLower(host)
	// Known Git hosts are repositories, not registries
	if _, ok := knownGitHosts[host]; ok {
		return false
	}
	// Explicit registry (has dot like ghcr.io) or port (has colon) or localhost
	if host == "localhost" || strings.Contains(host, ".") || strings.Contains(host, ":") {
		return true
	}
	// Ambiguous "owner/repo" pattern - require explicit tag or digest
	return hasExplicitTagOrDigest(target)
}

func imageHost(target string) string {
	if idx := strings.IndexRune(target, '/'); idx != -1 {
		return target[:idx]
	}
	return ""
}

func hasExplicitTagOrDigest(target string) bool {
	if strings.Contains(target, "@") {
		return true
	}
	colon := strings.LastIndex(target, ":")
	if colon == -1 {
		return false
	}
	slash := strings.LastIndex(target, "/")
	return colon > slash
}

func isAmbiguousDockerHubReference(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" || strings.Contains(target, "://") {
		return false
	}
	if strings.HasPrefix(strings.ToLower(target), "pkg:") {
		return false
	}
	if strings.Count(target, "/") != 1 {
		return false
	}
	host := strings.ToLower(imageHost(target))
	if host == "" {
		return false
	}
	if host == "localhost" || strings.Contains(host, ".") || strings.Contains(host, ":") {
		return false
	}
	if hasExplicitTagOrDigest(target) {
		return false
	}
	if _, ok := knownGitHosts[host]; ok {
		return false
	}
	if _, err := name.ParseReference(target, name.WeakValidation); err != nil {
		return false
	}
	return true
}

// resolveSourceOverride parses the --source flag value and returns the target kind
// and optional image source type.
//
// Source values:
//   - auto: automatic detection (default)
//   - purl: Package URL
//   - sbom: SBOM file
//   - dir: local directory
//   - git: Git repository
//   - image/remote: remote container registry
//   - docker-daemon: local Docker daemon
//   - tarball: Docker save tarball
//   - oci-layout: OCI image layout directory
func resolveSourceOverride(source string) (kind string, imageSource string, err error) {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "", "auto":
		return "", "", nil
	case "purl":
		return "purl", "", nil
	case "sbom":
		return "sbom", "", nil
	case "dir", "directory":
		return "dir", "", nil
	case "git", "repo", "repository":
		return "git", "", nil
	case "image", "container", "container-image", "remote", "registry", "image-remote":
		return "image", "remote", nil
	case "docker-daemon", "daemon", "local", "image-daemon":
		return "image", "docker-daemon", nil
	case "tarball", "archive", "oci-archive", "image-tarball":
		return "image", "tarball", nil
	case "oci-layout", "layout":
		return "image", "oci-layout", nil
	case "dockerfile", "containerfile":
		return "dockerfile", "", nil
	default:
		return "", "", fmt.Errorf("unknown --source %q; use auto, git, dir, sbom, purl, dockerfile, remote, docker-daemon, tarball, oci-layout", source)
	}
}

func gitRoot(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return "", false
	}
	path = filepath.Clean(path)
	for {
		if _, err := os.Stat(filepath.Join(path, ".git")); err == nil {
			return path, true
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", false
		}
		path = parent
	}
}

func warnRefIgnored(cmd *cobra.Command, targetKind string) {
	if cmd == nil || targetKind == "" {
		return
	}
	if !cmd.Flags().Changed("ref") {
		return
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Warning: --ref ignored for %s targets\n", targetKind)
}
