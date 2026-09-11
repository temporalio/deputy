package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	scalibrimage "github.com/google/osv-scalibr/artifact/image"
	layerimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/temporalio/deputy/internal/network"
	"github.com/temporalio/deputy/internal/targets"
)

// ContainerImageData wraps a SCALIBR image with its underlying v1.Image for config access.
// This allows downstream code to access both the SCALIBR scanning interface and the
// raw image configuration data (USER, ENV, ENTRYPOINT, etc.) for policy evaluation.
type ContainerImageData struct {
	// Image is the SCALIBR image interface used for vulnerability scanning.
	Image *layerimage.Image

	// V1Image is the underlying go-containerregistry image, if available.
	// This provides access to ConfigFile() for image configuration analysis.
	// May be nil for images loaded from tarball or OCI layout.
	V1Image v1.Image
}

// FS returns the filesystem view for SCALIBR scanning.
func (d *ContainerImageData) FS() scalibrfs.FS {
	if d == nil || d.Image == nil {
		return nil
	}
	return d.Image.FS()
}

// CleanUp releases resources associated with the image.
func (d *ContainerImageData) CleanUp() error {
	if d == nil || d.Image == nil {
		return nil
	}
	return d.Image.CleanUp()
}

// Labels implements the scalibrimage.Image interface.
func (d *ContainerImageData) Labels() map[string]string {
	if d == nil || d.Image == nil {
		return nil
	}
	return d.Image.Labels()
}

// Layers implements the scalibrimage.Image interface.
func (d *ContainerImageData) Layers() ([]scalibrimage.Layer, error) {
	if d == nil || d.Image == nil {
		return nil, nil
	}
	return d.Image.Layers()
}

// ChainLayers implements the scalibrimage.Image interface.
func (d *ContainerImageData) ChainLayers() ([]scalibrimage.ChainLayer, error) {
	if d == nil || d.Image == nil {
		return nil, nil
	}
	return d.Image.ChainLayers()
}

// ContainerImageData must satisfy the SCALIBR image interface: callers reach it
// through a type assertion, so a missing method would silently turn every image
// scan into "not a container image" instead of failing to build.
var _ scalibrimage.Image = (*ContainerImageData)(nil)

// V1 returns the underlying go-containerregistry v1.Image, if available.
// This method allows inventory.collector to access image configuration
// without importing the providers package directly.
func (d *ContainerImageData) V1() v1.Image {
	if d == nil {
		return nil
	}
	return d.V1Image
}

type imageTransport string

const (
	imageTransportRemote     imageTransport = "remote"
	imageTransportDocker     imageTransport = "docker-daemon"
	imageTransportTarball    imageTransport = "tarball"
	imageTransportOCITarball imageTransport = "oci-archive"
	imageTransportOCILayout  imageTransport = "oci-layout"
)

var imageSchemes = map[string]imageTransport{
	"docker":        imageTransportRemote,
	"oci":           imageTransportRemote,
	"container":     imageTransportRemote,
	"docker-daemon": imageTransportDocker,
	"tarball":       imageTransportTarball,
	"oci-archive":   imageTransportOCITarball,
	"oci-layout":    imageTransportOCILayout,
}

// priorityContainerImage determines detection order relative to other providers.
// Container images have priority 75, which is:
//   - Lower than local Git repos (100) - prefer Git if .git exists
//   - Higher than plain directories (50) - prefer image if scheme matches
//   - Higher than remote Git repos (10) - scheme detection is more explicit
//
// This ordering ensures explicit container schemes (docker://, oci://) take
// precedence over ambiguous targets that might be interpreted as remote repos.
const priorityContainerImage = 75

// knownPlatforms contains valid OS/architecture combinations for validation.
// This is not exhaustive but covers the most common platforms.
var knownPlatforms = map[string]map[string]bool{
	"linux": {
		"amd64":   true,
		"arm64":   true,
		"arm":     true,
		"386":     true,
		"ppc64le": true,
		"s390x":   true,
		"riscv64": true,
		"mips64":  true,
	},
	"windows": {
		"amd64": true,
		"arm64": true,
	},
	"darwin": {
		"amd64": true,
		"arm64": true,
	},
}

// containerImageProvider implements [targets.Provider] for container image references.
type containerImageProvider struct{}

func (containerImageProvider) Priority() int { return priorityContainerImage }

func (containerImageProvider) Detect(_ context.Context, target string) bool {
	// Check for explicit scheme (docker://, oci://, etc.)
	if _, _, ok := parseImageTarget(target); ok {
		return true
	}
	// Check for bare container image refs (alpine:3.19, ghcr.io/owner/app:v1)
	return targets.LooksLikeContainerRef(target)
}

func (containerImageProvider) Open(ctx context.Context, target string, opts map[string]string) (targets.Materialized, error) {
	transport, rawRef, ok := parseImageTarget(target)
	if !ok {
		return targets.Materialized{}, fmt.Errorf("image target %q is not supported; valid formats: docker://registry/image:tag, docker-daemon://image:tag, oci://registry/image:tag, tarball://path/to/image.tar, oci-layout://path/to/layout", target)
	}
	if strings.TrimSpace(rawRef) == "" {
		return targets.Materialized{}, fmt.Errorf("image target %q is missing a reference (expected format: scheme://image:tag or scheme://registry/image:tag)", target)
	}

	meta := targets.Descriptor{
		Kind:    targets.KindContainerImage,
		Target:  target,
		Options: opts,
	}

	var (
		img     *layerimage.Image
		v1Img   v1.Image // Underlying v1.Image for config access (may be nil for local sources)
		imgRef  *imageReference
		pathRef string
		err     error
	)

	// cleanupImage safely cleans up image resources on error paths.
	// Must be called explicitly on error before returning.
	cleanupImage := func() {
		if img == nil {
			return
		}
		if cleanup, ok := any(img).(interface{ CleanUp() error }); ok {
			if cleanupErr := cleanup.CleanUp(); cleanupErr != nil {
				slog.Debug("image cleanup failed", "target", target, "error", cleanupErr)
			}
		}
	}

	switch transport {
	case imageTransportDocker:
		imgRef, err = normalizeImageReference(rawRef)
		if err != nil {
			return targets.Materialized{}, fmt.Errorf("invalid docker daemon image reference %q: %w", rawRef, err)
		}
		img, err = layerimage.FromLocalDockerImage(imgRef.input, layerimage.DefaultConfig())
		if err != nil {
			return targets.Materialized{}, wrapDockerDaemonError(err, imgRef.input)
		}
		// Extract v1.Image from docker daemon for config access (USER, ENV, ENTRYPOINT, etc.)
		// This enables policy evaluation on docker-daemon-sourced images.
		daemonRef, parseErr := name.ParseReference(imgRef.input, name.WeakValidation)
		if parseErr == nil {
			if v1Img, err = daemon.Image(daemonRef, daemon.WithContext(ctx)); err != nil {
				slog.DebugContext(ctx, "docker daemon config extraction failed, policies requiring image.config will be limited",
					"image", imgRef.input,
					"error", err,
				)
				// Continue without v1Img - scanning still works, just without config policies
			}
		}
	case imageTransportTarball, imageTransportOCITarball:
		pathRef, err = filepath.Abs(rawRef)
		if err != nil {
			return targets.Materialized{}, fmt.Errorf("resolve absolute path for %q: %w", rawRef, err)
		}
		if err := validateImageTarballPath(transport, pathRef); err != nil {
			return targets.Materialized{}, err
		}
		img, err = layerimage.FromTarball(pathRef, layerimage.DefaultConfig())
		if err != nil {
			archiveType := "image tarball"
			if transport == imageTransportOCITarball {
				archiveType = "OCI archive"
			}
			return targets.Materialized{}, fmt.Errorf("load %s %q: %w", archiveType, pathRef, err)
		}
		// Extract v1.Image from tarball for config access (USER, ENV, ENTRYPOINT, etc.)
		// This enables policy evaluation on tarball-sourced images.
		if v1Img, err = tarball.ImageFromPath(pathRef, nil); err != nil {
			slog.DebugContext(ctx, "tarball config extraction failed, policies requiring image.config will be limited",
				"path", pathRef,
				"error", err,
			)
			// Continue without v1Img - scanning still works, just without config policies
		}
	case imageTransportOCILayout:
		pathRef, err = filepath.Abs(rawRef)
		if err != nil {
			return targets.Materialized{}, fmt.Errorf("resolve absolute path for %q: %w", rawRef, err)
		}
		img, v1Img, err = loadOCILayoutImage(ctx, pathRef, opts)
		if err != nil {
			return targets.Materialized{}, err
		}
	default:
		imgRef, err = normalizeImageReference(rawRef)
		if err != nil {
			return targets.Materialized{}, fmt.Errorf("invalid container image reference %q: %w", rawRef, err)
		}
		img, v1Img, err = loadRemoteImage(ctx, imgRef, opts)
		if err != nil {
			cleanupImage()
			return targets.Materialized{}, err
		}
	}

	if imgRef != nil {
		meta.Target = formatImageTarget(target, imgRef.normalized)
		if transport == imageTransportDocker {
			meta.Target = formatImageTarget(target, imgRef.input)
		}
		meta.Provenance = imageReferenceProvenance(imgRef)
		meta.Provenance["transport"] = string(transport)
	}
	if pathRef != "" {
		meta.Target = formatImageTarget(target, pathRef)
		meta.Provenance = map[string]string{
			"transport": string(transport),
			"path":      pathRef,
		}
	}
	if platform := strings.TrimSpace(opts["platform"]); platform != "" {
		if meta.Provenance == nil {
			meta.Provenance = map[string]string{}
		}
		meta.Provenance["platform"] = platform
	}

	// Wrap the image data with v1.Image for config access
	imgData := &ContainerImageData{
		Image:   img,
		V1Image: v1Img, // May be nil for non-remote transports
	}

	mat := targets.Materialized{
		FS:   img.FS(),
		Path: pathRef,
		Meta: meta,
		Data: imgData,
	}
	mat.Cleanup = func() {
		if cleanup, ok := any(img).(interface{ CleanUp() error }); ok {
			_ = cleanup.CleanUp()
		}
	}
	return mat, nil
}

type imageReference struct {
	input      string
	normalized string
	registry   string
	repository string
	tag        string
	digest     string
	ref        name.Reference
}

func normalizeImageReference(ref string) (*imageReference, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, fmt.Errorf("image reference is required")
	}
	parsed, err := name.ParseReference(ref, name.WeakValidation)
	if err != nil {
		return nil, fmt.Errorf("invalid image reference %q: %w", ref, err)
	}
	info := &imageReference{
		input:      ref,
		normalized: parsed.Name(),
		registry:   parsed.Context().RegistryStr(),
		repository: parsed.Context().RepositoryStr(),
		ref:        parsed,
	}
	switch v := parsed.(type) {
	case name.Tag:
		info.tag = v.TagStr()
	case name.Digest:
		info.digest = v.DigestStr()
	}
	return info, nil
}

func imageReferenceProvenance(ref *imageReference) map[string]string {
	if ref == nil {
		return map[string]string{}
	}
	prov := map[string]string{
		"image":      ref.normalized,
		"registry":   ref.registry,
		"repository": ref.repository,
	}
	if ref.input != "" && ref.input != ref.normalized {
		prov["image_input"] = ref.input
	}
	if ref.tag != "" {
		prov["tag"] = ref.tag
	}
	if ref.digest != "" {
		prov["digest"] = ref.digest
	}
	return prov
}

func parseImageTarget(target string) (imageTransport, string, bool) {
	// Check for explicit scheme (docker://, oci://, etc.)
	scheme, rest, hasScheme := strings.Cut(target, "://")
	if hasScheme {
		transport, ok := imageSchemes[strings.ToLower(scheme)]
		if !ok {
			return "", "", false
		}
		if transport == imageTransportRemote && strings.HasPrefix(rest, "/") {
			rest = strings.TrimPrefix(rest, "/")
		}
		return transport, rest, true
	}

	// Handle bare container refs (alpine:3.19, ghcr.io/owner/app:v1)
	// These default to remote registry transport
	if targets.LooksLikeContainerRef(target) {
		return imageTransportRemote, target, true
	}

	return "", "", false
}

func formatImageTarget(target, ref string) string {
	scheme, _, ok := strings.Cut(target, "://")
	if !ok {
		return ref
	}
	return scheme + "://" + ref
}

func validateImageTarballPath(transport imageTransport, path string) error {
	label := "image tarball"
	if transport == imageTransportOCITarball {
		label = "OCI archive"
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s %q does not exist", label, path)
		}
		return fmt.Errorf("failed to stat %s %q: %w", label, path, err)
	}
	if !info.IsDir() {
		return nil
	}
	if isOCIImageLayoutDir(path) {
		return fmt.Errorf("image path %q is an OCI layout directory; use oci-layout://%s instead", path, path)
	}
	return fmt.Errorf("%s %q is a directory; expected a tarball file", label, path)
}

func isOCIImageLayoutDir(path string) bool {
	if !isRegularFile(filepath.Join(path, "oci-layout")) {
		return false
	}
	if !isRegularFile(filepath.Join(path, "index.json")) {
		return false
	}
	return true
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func loadRemoteImage(ctx context.Context, ref *imageReference, opts map[string]string) (*layerimage.Image, v1.Image, error) {
	if ref == nil || ref.ref == nil {
		return nil, nil, fmt.Errorf("image reference is required")
	}
	remoteOpts, err := buildRemoteOptions(ctx, opts)
	if err != nil {
		return nil, nil, err
	}
	var img v1.Image
	switch r := ref.ref.(type) {
	case name.Digest:
		desc, err := remote.Get(r, remoteOpts...)
		if err != nil {
			return nil, nil, wrapRegistryError(err, r.Name())
		}
		img, err = desc.Image()
		if err != nil {
			return nil, nil, fmt.Errorf("parse image digest %s: %w", r.Name(), err)
		}
	default:
		var err error
		img, err = remote.Image(ref.ref, remoteOpts...)
		if err != nil {
			return nil, nil, wrapRegistryError(err, ref.ref.Name())
		}
	}
	layerImg, err := layerimage.FromV1Image(img, layerimage.DefaultConfig())
	if err != nil {
		return nil, nil, err
	}
	return layerImg, img, nil
}

// wrapRegistryError enriches registry errors with actionable guidance.
func wrapRegistryError(err error, imageName string) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for rate limiting errors
	if strings.Contains(errStr, "TOOMANYREQUESTS") || strings.Contains(errStr, "429") {
		return &RegistryError{
			Image:   imageName,
			Cause:   err,
			Message: "rate limit exceeded",
			Hint:    "authenticate with 'docker login' to increase rate limits, or wait and retry",
		}
	}

	// Check for authentication errors
	if strings.Contains(errStr, "UNAUTHORIZED") || strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "DENIED") || strings.Contains(errStr, "403") {
		return &RegistryError{
			Image:   imageName,
			Cause:   err,
			Message: "authentication required",
			Hint:    "run 'docker login' to authenticate, or check ~/.docker/config.json",
		}
	}

	// Check for not found errors
	if strings.Contains(errStr, "NOT_FOUND") || strings.Contains(errStr, "MANIFEST_UNKNOWN") ||
		strings.Contains(errStr, "NAME_UNKNOWN") {
		return &RegistryError{
			Image:   imageName,
			Cause:   err,
			Message: "image not found",
			Hint:    "verify the image name and tag are correct",
		}
	}

	// Default: wrap with image context
	return fmt.Errorf("pull image %s: %w", imageName, err)
}

// RegistryError provides actionable error messages for registry operations.
type RegistryError struct {
	Image   string
	Message string
	Hint    string
	Cause   error
}

func (e *RegistryError) Error() string {
	return fmt.Sprintf("pull image %s: %s (hint: %s)", e.Image, e.Message, e.Hint)
}

func (e *RegistryError) Unwrap() error {
	return e.Cause
}

// wrapDockerDaemonError enriches docker daemon errors with diagnostic hints.
func wrapDockerDaemonError(err error, imageName string) error {
	if err == nil {
		return nil
	}

	errStr := strings.ToLower(err.Error())

	// Check for daemon connection errors
	if strings.Contains(errStr, "cannot connect") || strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no such host") || strings.Contains(errStr, "dial unix") {
		return &DockerDaemonError{
			Image:   imageName,
			Cause:   err,
			Message: "cannot connect to Docker daemon",
			Hint:    "ensure Docker is running ('docker ps' to test) or check DOCKER_HOST environment variable",
		}
	}

	// Check for image not found errors
	if strings.Contains(errStr, "no such image") || strings.Contains(errStr, "not found") ||
		strings.Contains(errStr, "does not exist") {
		return &DockerDaemonError{
			Image:   imageName,
			Cause:   err,
			Message: "image not found in local Docker daemon",
			Hint:    "pull the image first ('docker pull " + imageName + "') or list available images ('docker images')",
		}
	}

	// Check for permission errors
	if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "access denied") {
		return &DockerDaemonError{
			Image:   imageName,
			Cause:   err,
			Message: "permission denied accessing Docker daemon",
			Hint:    "ensure your user is in the docker group ('sudo usermod -aG docker $USER') or run with sudo",
		}
	}

	// Default: wrap with image context
	return fmt.Errorf("load image from docker daemon %q: %w", imageName, err)
}

// DockerDaemonError provides actionable error messages for Docker daemon operations.
type DockerDaemonError struct {
	Image   string
	Message string
	Hint    string
	Cause   error
}

func (e *DockerDaemonError) Error() string {
	return fmt.Sprintf("docker daemon: %s for %q (hint: %s)", e.Message, e.Image, e.Hint)
}

func (e *DockerDaemonError) Unwrap() error {
	return e.Cause
}

// loadOCILayoutImage loads a container image from an OCI image layout directory.
// The directory must contain oci-layout and index.json files per the OCI Image Layout spec.
// If multiple images are present, use the "tag" option to select one by tag/digest.
// Returns both the SCALIBR image for scanning and v1.Image for config extraction.
func loadOCILayoutImage(ctx context.Context, path string, opts map[string]string) (*layerimage.Image, v1.Image, error) {
	if !isOCIImageLayoutDir(path) {
		return nil, nil, fmt.Errorf("path %q is not a valid OCI image layout directory (missing oci-layout or index.json)", path)
	}

	// Read the index.json to find available manifests
	indexPath := filepath.Join(path, "index.json")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read OCI layout index %q: %w", indexPath, err)
	}

	var index ociIndex
	if err := json.Unmarshal(indexData, &index); err != nil {
		return nil, nil, fmt.Errorf("parse OCI layout index %q: %w", indexPath, err)
	}

	if len(index.Manifests) == 0 {
		return nil, nil, fmt.Errorf("OCI layout %q contains no manifests", path)
	}

	// Select the manifest to use
	manifest, err := selectOCIManifest(index.Manifests, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("select manifest from OCI layout %q: %w", path, err)
	}

	// Load the image using the manifest digest
	// The tarball loader handles OCI layout directories when given the blobs path
	blobPath := filepath.Join(path, "blobs", manifest.Digest.Algorithm, manifest.Digest.Encoded)
	if _, err := os.Stat(blobPath); err != nil {
		return nil, nil, fmt.Errorf("manifest blob not found at %q: %w", blobPath, err)
	}

	// Use FromTarball which can handle OCI layouts
	img, err := layerimage.FromTarball(path, layerimage.DefaultConfig())
	if err != nil {
		return nil, nil, fmt.Errorf("load OCI layout image from %q: %w", path, err)
	}

	// Extract v1.Image from OCI layout for config access (USER, ENV, ENTRYPOINT, etc.)
	// This enables policy evaluation on OCI-layout-sourced images.
	var v1Img v1.Image
	layoutPath, err := layout.FromPath(path)
	if err != nil {
		slog.DebugContext(ctx, "OCI layout config extraction failed, policies requiring image.config will be limited",
			"path", path,
			"error", err,
		)
	} else {
		// Try to get the image by the selected manifest digest
		digestStr := manifest.Digest.Algorithm + ":" + manifest.Digest.Encoded
		hash, err := v1.NewHash(digestStr)
		if err == nil {
			if v1Img, err = layoutPath.Image(hash); err != nil {
				slog.DebugContext(ctx, "OCI layout image extraction failed",
					"path", path,
					"digest", digestStr,
					"error", err,
				)
			}
		}
	}

	return img, v1Img, nil
}

// ociIndex represents the structure of an OCI image layout index.json.
type ociIndex struct {
	SchemaVersion int           `json:"schemaVersion"`
	Manifests     []ociManifest `json:"manifests"`
}

// ociManifest represents a manifest entry in index.json.
type ociManifest struct {
	MediaType   string            `json:"mediaType"`
	Digest      ociDigest         `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Platform    *ociPlatform      `json:"platform,omitempty"`
}

// ociDigest represents a digest in algorithm:encoded format.
type ociDigest struct {
	Algorithm string
	Encoded   string
}

func (d *ociDigest) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	alg, enc, ok := strings.Cut(s, ":")
	if !ok {
		return fmt.Errorf("invalid digest format %q", s)
	}
	d.Algorithm = alg
	d.Encoded = enc
	return nil
}

// ociPlatform represents platform information in a manifest.
type ociPlatform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

// selectOCIManifest selects the appropriate manifest based on options.
func selectOCIManifest(manifests []ociManifest, opts map[string]string) (ociManifest, error) {
	if len(manifests) == 1 {
		return manifests[0], nil
	}

	// Check for tag selection via annotations
	if opts != nil {
		if tag := strings.TrimSpace(opts["tag"]); tag != "" {
			for _, m := range manifests {
				if refName := m.Annotations["org.opencontainers.image.ref.name"]; refName == tag {
					return m, nil
				}
			}
			return ociManifest{}, fmt.Errorf("no manifest with tag %q found", tag)
		}

		// Check for platform selection
		if platform := strings.TrimSpace(opts["platform"]); platform != "" {
			parts := strings.Split(platform, "/")
			if len(parts) >= 2 {
				wantOS := parts[0]
				wantArch := parts[1]
				wantVariant := ""
				if len(parts) >= 3 {
					wantVariant = parts[2]
				}
				for _, m := range manifests {
					if m.Platform != nil &&
						m.Platform.OS == wantOS &&
						m.Platform.Architecture == wantArch &&
						(wantVariant == "" || m.Platform.Variant == wantVariant) {
						return m, nil
					}
				}
				// Collect available platforms for helpful error message
				available := make([]string, 0, len(manifests))
				for _, m := range manifests {
					if m.Platform != nil {
						p := m.Platform.OS + "/" + m.Platform.Architecture
						if m.Platform.Variant != "" {
							p += "/" + m.Platform.Variant
						}
						available = append(available, p)
					}
				}
				if len(available) > 0 {
					return ociManifest{}, fmt.Errorf("no manifest for platform %q found; available platforms: %s", platform, strings.Join(available, ", "))
				}
				return ociManifest{}, fmt.Errorf("no manifest for platform %q found", platform)
			}
		}
	}

	// Try to match the local machine's platform for better default behavior.
	// This provides a more intuitive experience for users scanning images locally.
	localOS := runtime.GOOS
	localArch := runtime.GOARCH
	// Normalize architecture names (Go uses different names than OCI)
	if localArch == "arm64" {
		// Go uses arm64, OCI typically uses aarch64 or arm64
		// Most registries use arm64 (Docker-style) not aarch64 (OCI-style)
	}

	for _, m := range manifests {
		if m.Platform != nil &&
			m.Platform.OS == localOS &&
			m.Platform.Architecture == localArch {
			// Found a match for local platform
			slog.Info("selected manifest matching local platform",
				"platform", formatPlatform(m.Platform),
				"hint", "use --platform for explicit selection in CI environments",
			)
			return m, nil
		}
	}

	// No local platform match found - fall back with deterministic preference.
	// For multi-arch images, prefer linux/amd64 as the most common deployment target,
	// then linux/arm64, then first manifest. This ensures reproducible scans in CI/CD
	// where the scanning environment may differ from deployment.
	platforms := make([]string, 0, len(manifests))
	for _, m := range manifests {
		if m.Platform != nil {
			p := m.Platform.OS + "/" + m.Platform.Architecture
			if m.Platform.Variant != "" {
				p += "/" + m.Platform.Variant
			}
			platforms = append(platforms, p)
		}
	}

	// Prefer linux/amd64 as the most common deployment platform
	for _, m := range manifests {
		if m.Platform != nil &&
			m.Platform.OS == "linux" &&
			m.Platform.Architecture == "amd64" {
			slog.Info("no local platform match, selected linux/amd64 as default",
				"available", platforms,
				"selected", formatPlatform(m.Platform),
				"hint", "use --platform for explicit selection",
			)
			return m, nil
		}
	}

	// Second preference: linux/arm64 (common for ARM-based deployments)
	for _, m := range manifests {
		if m.Platform != nil &&
			m.Platform.OS == "linux" &&
			m.Platform.Architecture == "arm64" {
			slog.Info("no local platform match, selected linux/arm64 as fallback",
				"available", platforms,
				"selected", formatPlatform(m.Platform),
				"hint", "use --platform for explicit selection",
			)
			return m, nil
		}
	}

	// Last resort: first manifest
	slog.Warn("no common platform found, using first manifest",
		"count", len(manifests),
		"platforms", platforms,
		"selected", formatPlatform(manifests[0].Platform),
		"hint", "use --platform to select specific manifest for reproducible scans",
	)
	return manifests[0], nil
}

// formatPlatform returns a human-readable string for a platform, or "unknown" if nil.
func formatPlatform(p *ociPlatform) string {
	if p == nil {
		return "unknown"
	}
	s := p.OS + "/" + p.Architecture
	if p.Variant != "" {
		s += "/" + p.Variant
	}
	return s
}

func buildRemoteOptions(ctx context.Context, opts map[string]string) ([]remote.Option, error) {
	// Authentication uses the Docker credential keychain by default.
	// This supports:
	//   - ~/.docker/config.json credentials
	//   - Docker credential helpers (gcloud, ecr-login, etc.)
	//   - Environment variables (DOCKER_CONFIG)
	// See: https://pkg.go.dev/github.com/google/go-containerregistry/pkg/authn
	remoteOpts := []remote.Option{
		remote.WithTransport(network.SafeTransport()),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}

	// Add retry support for transient failures and rate limiting.
	// Default status codes are: 408, 500, 502, 503, 504, 499, 522
	// We add 429 (Too Many Requests) for rate limit handling.
	remoteOpts = append(remoteOpts,
		remote.WithRetryBackoff(remote.Backoff{
			Duration: 2 * time.Second, // Start with 2s delay
			Factor:   2.0,             // Double each time
			Jitter:   0.1,             // Add 10% jitter
			Steps:    5,               // Up to 5 retries (2s, 4s, 8s, 16s, 32s)
		}),
		remote.WithRetryStatusCodes(
			http.StatusRequestTimeout,      // 408
			http.StatusTooManyRequests,     // 429 - rate limiting
			http.StatusInternalServerError, // 500
			http.StatusBadGateway,          // 502
			http.StatusServiceUnavailable,  // 503
			http.StatusGatewayTimeout,      // 504
		),
	)

	if ctx != nil {
		remoteOpts = append(remoteOpts, remote.WithContext(ctx))
	}
	if opts == nil {
		return remoteOpts, nil
	}

	platform := strings.TrimSpace(opts["platform"])
	if platform == "" {
		return remoteOpts, nil
	}

	p, err := parsePlatform(platform)
	if err != nil {
		return nil, err
	}
	remoteOpts = append(remoteOpts, remote.WithPlatform(p))
	return remoteOpts, nil
}

// parsePlatform parses and validates a platform string in the format os/arch or os/arch/variant.
func parsePlatform(platform string) (v1.Platform, error) {
	platform = strings.TrimSpace(platform)
	if platform == "" {
		return v1.Platform{}, fmt.Errorf("platform is required")
	}

	parts := strings.Split(platform, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return v1.Platform{}, fmt.Errorf("invalid platform %q: expected os/arch or os/arch/variant (e.g., linux/amd64)", platform)
	}

	osName := strings.TrimSpace(parts[0])
	arch := strings.TrimSpace(parts[1])
	variant := ""
	if len(parts) == 3 {
		variant = strings.TrimSpace(parts[2])
	}

	if osName == "" {
		return v1.Platform{}, fmt.Errorf("invalid platform %q: OS cannot be empty", platform)
	}
	if arch == "" {
		return v1.Platform{}, fmt.Errorf("invalid platform %q: architecture cannot be empty", platform)
	}

	// Validate against known platforms for better error messages
	if archSet, ok := knownPlatforms[osName]; ok {
		if !archSet[arch] {
			// OS is known but architecture is not - warn but allow (could be valid variant)
			knownArchs := make([]string, 0, len(archSet))
			for a := range archSet {
				knownArchs = append(knownArchs, a)
			}
			slog.Debug("unknown architecture for OS",
				"platform", platform,
				"os", osName,
				"arch", arch,
				"known_architectures", knownArchs,
			)
		}
	} else {
		// Unknown OS - warn but allow (new OS variants may exist)
		knownOSes := make([]string, 0, len(knownPlatforms))
		for os := range knownPlatforms {
			knownOSes = append(knownOSes, os)
		}
		slog.Debug("unknown operating system in platform",
			"platform", platform,
			"os", osName,
			"known_operating_systems", knownOSes,
		)
	}

	return v1.Platform{
		OS:           osName,
		Architecture: arch,
		Variant:      variant,
	}, nil
}

var _ targets.Provider = (*containerImageProvider)(nil)
var _ targets.PriorityProvider = (*containerImageProvider)(nil)
var _ scalibrimage.Image = (*layerimage.Image)(nil)
