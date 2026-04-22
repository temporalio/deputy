package pin

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

const (
	// EcosystemContainerImage is the ecosystem identifier for container image pinning.
	EcosystemContainerImage = "container-image"
)

// Compile-time interface check.
var _ Strategy = (*ContainerStrategy)(nil)

// digestRe matches a sha256 container image digest.
var digestRe = regexp.MustCompile(`sha256:[a-fA-F0-9]{64}`)

// ContainerStrategy implements the Strategy interface for container image
// digest pinning. It discovers image references in:
//
//   - Dockerfiles (FROM statements)
//   - GitHub Actions workflows (docker:// uses, container:, services:)
//   - Composite action manifests (docker:// uses in steps)
//
// It resolves tags to sha256 digests via OCI registry HEAD requests using
// the Docker credential keychain for auth. No special token is needed for
// public images; private registries use credentials from ~/.docker/config.json.
type ContainerStrategy struct {
	// resolveDigestFunc resolves an image reference to its digest.
	// Defaults to ociResolveDigest. Tests can override this.
	resolveDigestFunc func(ctx context.Context, imageRef string) (string, error)
}

// NewContainerStrategy creates a Strategy for container image digest pinning.
func NewContainerStrategy() *ContainerStrategy {
	s := &ContainerStrategy{}
	s.resolveDigestFunc = ociResolveDigest
	return s
}

// Ecosystem implements Strategy.
func (s *ContainerStrategy) Ecosystem() string { return EcosystemContainerImage }

// IsPinned implements Strategy. A container image ref is pinned when its
// version contains a sha256 digest.
func (s *ContainerStrategy) IsPinned(ref Ref) bool {
	return strings.Contains(ref.Version, "sha256:")
}

// ShouldSkip implements Strategy.
func (s *ContainerStrategy) ShouldSkip(ref Ref) (bool, string) {
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

// Discover implements Strategy. It finds container image references across
// Dockerfiles and GitHub Actions workflow files.
func (s *ContainerStrategy) Discover(ctx context.Context, fsys scalibrfs.FS) ([]Ref, error) {
	var refs []Ref
	seen := map[string]bool{}

	addRef := func(r Ref) {
		key := dedupeKey(r)
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
			if shouldSkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if isSymlink(d) || !isDockerfile(d.Name()) {
			return nil
		}
		found, err := discoverDockerfileRefs(fsys, relPath)
		if err != nil {
			return nil // skip unparseable files
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
			if !isWorkflowFile(relPath) {
				return nil
			}
			found, err := discoverWorkflowContainerRefs(fsys, relPath)
			if err != nil {
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

// Resolve implements Strategy. It resolves an image tag to a sha256 digest
// via an OCI registry HEAD request.
func (s *ContainerStrategy) Resolve(ctx context.Context, ref Ref) (pinnedValue, versionTag string, err error) {
	tag := ref.Version
	imageRef := ref.Name + ":" + tag
	digest, err := s.resolveDigestFunc(ctx, imageRef)
	if err != nil {
		return "", "", fmt.Errorf("resolving digest for %s: %w", imageRef, err)
	}
	return digest, tag, nil
}

// Verify implements Strategy. Container image signature verification
// (e.g., cosign/sigstore) is not yet implemented.
func (s *ContainerStrategy) Verify(_ context.Context, _ Ref) (*Verification, error) {
	return nil, nil
}

// ResolveUpdate implements Strategy. It re-resolves a pinned image tag to
// check if the digest has changed (e.g., a security patch was pushed to
// the same tag).
func (s *ContainerStrategy) ResolveUpdate(ctx context.Context, ref Ref) (pinnedValue, newVersionTag, currentVersionTag string, err error) {
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

// Rewrite implements Strategy. It rewrites container image references to
// include sha256 digest pins, preserving the original tag for readability.
func (s *ContainerStrategy) Rewrite(root *os.Root, relPath string, updates []Update) error {
	return rewriteContainerRefs(root, relPath, updates)
}

// --- Discovery helpers ---

// discoverDockerfileRefs extracts container image refs from FROM statements.
func discoverDockerfileRefs(fsys scalibrfs.FS, relPath string) ([]Ref, error) {
	content, err := fs.ReadFile(fsys, relPath)
	if err != nil {
		return nil, err
	}

	var refs []Ref
	// Match FROM with optional --platform, image:tag or image@digest, optional AS.
	fromRe := regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=[^\s]+\s+)?(\S+)`)

	for _, match := range fromRe.FindAllSubmatch(content, -1) {
		raw := string(match[1])
		imgName, version := splitImageRef(raw)
		if imgName == "" || strings.ToLower(imgName) == "scratch" {
			continue
		}
		refs = append(refs, Ref{
			Ecosystem: EcosystemContainerImage,
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
func discoverWorkflowContainerRefs(fsys scalibrfs.FS, relPath string) ([]Ref, error) {
	content, err := fs.ReadFile(fsys, relPath)
	if err != nil {
		return nil, err
	}

	var root map[string]any
	if err := yaml.Unmarshal(content, &root); err != nil {
		return nil, err
	}

	var refs []Ref

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
				refs = append(refs, Ref{
					Ecosystem: EcosystemContainerImage,
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
						refs = append(refs, Ref{
							Ecosystem: EcosystemContainerImage,
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
				refs = append(refs, Ref{
					Ecosystem: EcosystemContainerImage,
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

// splitImageRef splits an image reference into name and version (tag or
// tag@digest or digest). Handles registry-qualified names.
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

// --- Rewrite ---

// rewriteContainerRefs rewrites container image references in a file to
// include sha256 digest pins.
func rewriteContainerRefs(root *os.Root, relPath string, updates []Update) error {
	if len(updates) == 0 {
		return nil
	}

	rootFS := root.FS()
	info, err := fs.Stat(rootFS, relPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", relPath, err)
	}

	content, err := fs.ReadFile(rootFS, relPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", relPath, err)
	}

	contentStr := string(content)
	modified := false

	for _, u := range updates {
		if u.Name == "" || u.PinnedValue == "" || u.VersionTag == "" {
			continue
		}
		if !digestRe.MatchString(u.PinnedValue) {
			return fmt.Errorf("pinned value %q for %s is not a valid digest", u.PinnedValue, u.Name)
		}

		// Match NAME:TAG with optional existing @sha256:digest.
		pattern := fmt.Sprintf(
			`%s:%s(@sha256:[a-fA-F0-9]+)?`,
			regexp.QuoteMeta(u.Name), regexp.QuoteMeta(u.VersionTag),
		)
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("compiling regex for %s: %w", u.Name, err)
		}

		replacement := fmt.Sprintf("%s:%s@%s", u.Name, u.VersionTag, u.PinnedValue)
		newContent := re.ReplaceAllString(contentStr, replacement)
		if newContent != contentStr {
			contentStr = newContent
			modified = true
		}
	}

	if !modified {
		return nil
	}

	f, err := root.OpenFile(relPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return fmt.Errorf("writing %s: %w", relPath, err)
	}
	defer f.Close()

	_, err = f.Write([]byte(contentStr))
	return err
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
func isDockerfile(name string) bool {
	lower := strings.ToLower(name)
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
