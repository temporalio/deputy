package container

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/picatz/deputy/internal/pin"
)

const (
	// Ecosystem is the ecosystem identifier for container image pinning.
	Ecosystem = "container-image"
)

// Compile-time interface check.
var _ pin.Strategy = (*Strategy)(nil)

// digestRe matches a sha256 container image digest.
var digestRe = regexp.MustCompile(`sha256:[a-fA-F0-9]{64}`)

// fromRe matches Dockerfile FROM statements with optional --platform flag.
var fromRe = regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=[^\s]+\s+)?(\S+)`)

// Strategy implements the pin.Strategy interface for container image
// digest pinning. It discovers image references in:
//
//   - Dockerfiles (FROM statements)
//   - GitHub Actions workflows (docker:// uses, container:, services:)
//   - Composite action manifests (docker:// uses in steps)
//
// It resolves tags to sha256 digests via OCI registry HEAD requests using
// the Docker credential keychain for auth. No special token is needed for
// public images; private registries use credentials from ~/.docker/config.json.
type Strategy struct {
	// resolveDigestFunc resolves an image reference to its digest.
	// Defaults to ociResolveDigest. Tests can override this.
	resolveDigestFunc func(ctx context.Context, imageRef string) (string, error)
}

// NewStrategy creates a Strategy for container image digest pinning.
func NewStrategy() *Strategy {
	s := &Strategy{}
	s.resolveDigestFunc = ociResolveDigest
	return s
}

// NewStrategyWithResolver creates a Strategy with a custom digest resolver.
// This is intended for testing; production callers should use [NewStrategy].
func NewStrategyWithResolver(resolve func(ctx context.Context, imageRef string) (string, error)) *Strategy {
	return &Strategy{resolveDigestFunc: resolve}
}

// Ecosystem implements pin.Strategy.
func (s *Strategy) Ecosystem() string { return Ecosystem }

// IsPinned implements pin.Strategy. A container image ref is pinned when its
// version contains a sha256 digest.
func (s *Strategy) IsPinned(ref pin.Ref) bool {
	return strings.Contains(ref.Version, "sha256:")
}

// ShouldSkip implements pin.Strategy.
func (s *Strategy) ShouldSkip(ref pin.Ref) (bool, string) {
	v := ref.Version
	if v == "" {
		return true, "untagged image (add explicit tag first)"
	}
	if strings.Contains(v, "${{") || strings.Contains(v, "${") {
		return true, "expression ref"
	}
	lower := strings.ToLower(ref.Name)
	if lower == "scratch" {
		return true, "scratch image"
	}
	return false, ""
}

// Discover implements pin.Strategy. It finds container image references across
// Dockerfiles and GitHub Actions workflow files.
func (s *Strategy) Discover(ctx context.Context, fsys scalibrfs.FS) ([]pin.Ref, error) {
	var refs []pin.Ref
	seen := map[string]bool{}

	addRef := func(r pin.Ref) {
		key := pin.DedupeKey(r)
		if !seen[key] {
			seen[key] = true
			refs = append(refs, r)
		}
	}

	// Phase 1: Scan Dockerfiles.
	err := fs.WalkDir(fsys, ".", func(relPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if pin.ShouldSkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if pin.IsSymlink(d) || !isDockerfile(d.Name()) {
			return nil
		}
		found, err := discoverDockerfileRefs(fsys, relPath)
		if err != nil {
			slog.Debug("skipping unparseable Dockerfile", "path", relPath, "error", err)
			return nil
		}
		for _, r := range found {
			addRef(r)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanning Dockerfiles: %w", err)
	}

	// Phase 2: Scan workflow files for docker:// uses, container:, services:.
	if info, err := fs.Stat(fsys, ".github/workflows"); err == nil && info.IsDir() {
		err := fs.WalkDir(fsys, ".github/workflows", func(relPath string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if !pin.IsWorkflowFile(relPath) {
				return nil
			}
			found, err := discoverWorkflowContainerRefs(fsys, relPath)
			if err != nil {
				slog.Debug("skipping unparseable workflow", "path", relPath, "error", err)
				return nil
			}
			for _, r := range found {
				addRef(r)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("scanning workflows: %w", err)
		}
	}

	return refs, nil
}

// Resolve implements pin.Strategy. It resolves an image tag to a sha256 digest
// via an OCI registry HEAD request.
func (s *Strategy) Resolve(ctx context.Context, ref pin.Ref) (pinnedValue, versionTag string, err error) {
	tag := ref.Version
	imageRef := ref.Name + ":" + tag
	digest, err := s.resolveDigestFunc(ctx, imageRef)
	if err != nil {
		return "", "", fmt.Errorf("resolving digest for %s: %w", imageRef, err)
	}
	return digest, tag, nil
}

// Verify implements pin.Strategy. Container image signature verification
// (e.g., cosign/sigstore) is not yet implemented.
func (s *Strategy) Verify(_ context.Context, _ pin.Ref) (*pin.Verification, error) {
	return nil, nil
}

// ResolveUpdate implements pin.Strategy. It re-resolves a pinned image tag to
// check if the digest has changed (e.g., a security patch was pushed to
// the same tag).
func (s *Strategy) ResolveUpdate(ctx context.Context, ref pin.Ref) (pinnedValue, newVersionTag, currentVersionTag string, err error) {
	tag, currentDigest := splitTagDigest(ref.Version)
	if tag == "" {
		// Digest-only ref (no tag) — can't check for updates.
		return ref.Version, "", "", nil
	}

	imageRef := ref.Name + ":" + tag
	latestDigest, err := s.resolveDigestFunc(ctx, imageRef)
	if err != nil {
		return "", "", "", fmt.Errorf("resolving update for %s: %w", imageRef, err)
	}

	if latestDigest == currentDigest {
		return ref.Version, tag, tag, nil // no change
	}

	return latestDigest, tag, tag, nil
}

// Rewrite implements pin.Strategy. It rewrites container image references to
// include sha256 digest pins, preserving the original tag for readability.
func (s *Strategy) Rewrite(root *os.Root, relPath string, updates []pin.Update) error {
	return rewriteContainerRefs(root, relPath, updates)
}

// --- Discovery helpers ---

// discoverDockerfileRefs extracts container image refs from FROM statements.
func discoverDockerfileRefs(fsys scalibrfs.FS, relPath string) ([]pin.Ref, error) {
	content, err := fs.ReadFile(fsys, relPath)
	if err != nil {
		return nil, err
	}

	var refs []pin.Ref
	for _, match := range fromRe.FindAllSubmatch(content, -1) {
		raw := string(match[1])
		imgName, version := splitImageRef(raw)
		if imgName == "" || strings.ToLower(imgName) == "scratch" {
			continue
		}
		refs = append(refs, pin.Ref{
			Ecosystem: Ecosystem,
			Name:      imgName,
			Version:   version,
			FilePath:  relPath,
			Raw:       raw,
		})
	}
	return refs, nil
}

// discoverWorkflowContainerRefs extracts docker:// uses and container/services
// image refs from a GitHub Actions workflow file.
func discoverWorkflowContainerRefs(fsys scalibrfs.FS, relPath string) ([]pin.Ref, error) {
	content, err := fs.ReadFile(fsys, relPath)
	if err != nil {
		return nil, err
	}

	var root map[string]any
	if err := yaml.Unmarshal(content, &root); err != nil {
		return nil, err
	}

	var refs []pin.Ref

	jobs, _ := root["jobs"].(map[string]any)
	for _, jobRaw := range jobs {
		job, ok := jobRaw.(map[string]any)
		if !ok {
			continue
		}

		// Job-level container: field.
		if c := extractContainerImage(job, "container"); c != "" {
			imgName, version := splitImageRef(c)
			if imgName != "" && version != "" {
				refs = append(refs, pin.Ref{
					Ecosystem: Ecosystem,
					Name:      imgName,
					Version:   version,
					FilePath:  relPath,
					Raw:       c,
				})
			}
		}

		// Job-level services: field.
		if services, ok := job["services"].(map[string]any); ok {
			for _, svcRaw := range services {
				svc, ok := svcRaw.(map[string]any)
				if !ok {
					continue
				}
				if img, ok := svc["image"].(string); ok {
					img = strings.TrimSpace(img)
					imgName, version := splitImageRef(img)
					if imgName != "" && version != "" {
						refs = append(refs, pin.Ref{
							Ecosystem: Ecosystem,
							Name:      imgName,
							Version:   version,
							FilePath:  relPath,
							Raw:       img,
						})
					}
				}
			}
		}

		// Step-level docker:// uses.
		steps, _ := job["steps"].([]any)
		for _, stepRaw := range steps {
			step, ok := stepRaw.(map[string]any)
			if !ok {
				continue
			}
			usesStr, ok := step["uses"].(string)
			if !ok {
				continue
			}
			usesStr = strings.TrimSpace(usesStr)
			if !strings.HasPrefix(usesStr, "docker://") {
				continue
			}
			raw := strings.TrimPrefix(usesStr, "docker://")
			imgName, version := splitImageRef(raw)
			if imgName != "" && version != "" {
				refs = append(refs, pin.Ref{
					Ecosystem: Ecosystem,
					Name:      imgName,
					Version:   version,
					FilePath:  relPath,
					Raw:       raw,
				})
			}
		}
	}

	return refs, nil
}

// extractContainerImage gets the image string from a container field,
// handling both short form (string) and long form (map with image key).
func extractContainerImage(job map[string]any, key string) string {
	v, ok := job[key]
	if !ok {
		return ""
	}
	switch c := v.(type) {
	case string:
		return strings.TrimSpace(c)
	case map[string]any:
		if img, ok := c["image"].(string); ok {
			return strings.TrimSpace(img)
		}
	}
	return ""
}

// --- Image reference parsing ---

// SplitImageRef splits an image reference into name and version (tag or
// tag@digest or digest). Handles registry-qualified names. Exported for
// use by other packages that need to parse container image references.
//
//	"alpine:3.19"                      → ("alpine", "3.19")
//	"alpine:3.19@sha256:abc..."        → ("alpine", "3.19@sha256:abc...")
//	"alpine@sha256:abc..."             → ("alpine", "sha256:abc...")
//	"ghcr.io/owner/image:v1"           → ("ghcr.io/owner/image", "v1")
//	"alpine"                           → ("alpine", "")
func splitImageRef(raw string) (imgName, version string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}

	// Handle digest: everything after @ is part of the version.
	if idx := strings.Index(raw, "@"); idx >= 0 {
		before := raw[:idx]
		after := raw[idx+1:]
		imgName, tag := splitNameTag(before)
		if tag != "" {
			return imgName, tag + "@" + after
		}
		return imgName, after
	}

	return splitNameTag(raw)
}

// splitNameTag splits "name:tag" handling registry ports (e.g., localhost:5000/app:v1).
func splitNameTag(s string) (imgName, tag string) {
	// Find the last colon. But we need to distinguish registry ports from tags.
	// A colon is a tag separator if it's after the last slash.
	lastSlash := strings.LastIndex(s, "/")
	lastColon := strings.LastIndex(s, ":")
	if lastColon > lastSlash {
		return s[:lastColon], s[lastColon+1:]
	}
	return s, ""
}

// splitTagDigest splits a pinned version "tag@sha256:abc..." into tag and digest.
// Returns ("", version) if no @ separator is found.
func splitTagDigest(version string) (tag, digest string) {
	if idx := strings.Index(version, "@"); idx >= 0 {
		return version[:idx], version[idx+1:]
	}
	// Digest-only (no tag).
	if strings.HasPrefix(version, "sha256:") {
		return "", version
	}
	return version, ""
}

// --- Digest resolution ---

// ociResolveDigest resolves an image reference to its sha256 digest via
// an OCI registry HEAD request. Uses the Docker credential keychain
// (~/.docker/config.json) for authentication.
func ociResolveDigest(ctx context.Context, imageRef string) (string, error) {
	ref, err := name.ParseReference(imageRef, name.WeakValidation)
	if err != nil {
		return "", fmt.Errorf("parsing image reference %q: %w", imageRef, err)
	}
	desc, err := remote.Head(ref,
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	)
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), nil
}

// --- File detection ---

// isDockerfile returns true if the filename looks like a Dockerfile.
func isDockerfile(n string) bool {
	lower := strings.ToLower(n)
	if lower == "dockerfile" {
		return true
	}
	if strings.HasPrefix(lower, "dockerfile.") {
		return true
	}
	if strings.HasSuffix(lower, ".dockerfile") {
		return true
	}
	return false
}

