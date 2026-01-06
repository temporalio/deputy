package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/picatz/deputy/internal/container/image"
	"github.com/picatz/deputy/internal/policy"
	"github.com/picatz/deputy/internal/report"
	"github.com/picatz/deputy/internal/scan"
	"github.com/picatz/deputy/internal/targets"
	"go.opentelemetry.io/otel/trace"
)

const (
	ociOperationManifest = "manifest"
	ociOperationBlob     = "blob"
	ociOperationTags     = "tags"
	ociOperationPing     = "ping"
	ociOperationCatalog  = "catalog"
	ociOperationUpload   = "upload"
	ociOperationUnknown  = "unknown"
)

type ociHandlerOptions struct {
	imageCache  ImageScanCache
	digestCache DigestResolutionCache
	scanner     imageScanner
	resolveHead func(context.Context, name.Reference) (string, error)
}

type imageScanner interface {
	ScanContainerImage(context.Context, string, map[string]string, scan.Options) (*scan.Execution, error)
}

type ociHandler struct {
	policies    PolicyEvaluator
	proxy       *httputil.ReverseProxy
	scanner     imageScanner
	imageCache  ImageScanCache
	digestCache DigestResolutionCache
	resolveHead func(context.Context, name.Reference) (string, error)
	registry    string
}

// NewOCIHandler creates a handler for OCI registry proxying with policy evaluation.
func NewOCIHandler(upstream string, policies PolicyEvaluator) (http.Handler, error) {
	return newOCIHandler(upstream, policies, nil)
}

func newOCIHandler(upstream string, policies PolicyEvaluator, opts *ociHandlerOptions) (http.Handler, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", upstream, err)
	}
	var scanner imageScanner = scan.NewService()
	imgCache := getImageScanCache(nil)
	digCache := getDigestResolutionCache(nil)
	resolveHead := resolveRemoteDigest
	if opts != nil {
		if opts.scanner != nil {
			scanner = opts.scanner
		}
		if opts.imageCache != nil {
			imgCache = getImageScanCache(opts.imageCache)
		}
		if opts.digestCache != nil {
			digCache = getDigestResolutionCache(opts.digestCache)
		}
		if opts.resolveHead != nil {
			resolveHead = opts.resolveHead
		}
	}
	return &ociHandler{
		policies:    policies,
		proxy:       newUpstreamReverseProxy(u, "oci", getSharedTransport()),
		scanner:     scanner,
		imageCache:  imgCache,
		digestCache: digCache,
		resolveHead: resolveHead,
		registry:    u.Host,
	}, nil
}

func (h *ociHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := parseOCIRequestPath(r.URL.Path)
	payload := h.buildPayload(r.Context(), info, r.URL.Path)
	if info.Operation == ociOperationManifest && info.Repository != "" && info.Reference != "" {
		result, scanErr := h.scanImageForPolicy(r.Context(), info)
		if len(result.Vulnerabilities) > 0 {
			payload["vulnerabilities"] = result.Vulnerabilities
		}
		if target, ok := payload["target"].(map[string]any); ok {
			target["scan_cached"] = result.Cached
			if scanErr != nil {
				target["scan_error"] = scanErr.Error()
			}
			if result.Digest != "" {
				if prov, ok := target["provenance"].(map[string]any); ok {
					prov["digest"] = result.Digest
				}
			}
		}
		if result.Digest != "" {
			if req, ok := payload["request"].(map[string]any); ok {
				req["digest"] = result.Digest
			}
			if image, ok := payload["image"].(map[string]any); ok {
				image["digest"] = result.Digest
				if image["reference"] == "" {
					image["reference"] = result.Digest
				}
			}
		}
		// Merge ImageInfo into image payload for policy evaluation.
		// This enables policies to access image.config.user, image.config.is_root,
		// image.metadata.layer_count, image.history, etc.
		if result.ImageInfo != nil {
			if image, ok := payload["image"].(map[string]any); ok {
				for key, val := range result.ImageInfo {
					// Only add keys not already present (provenance takes precedence)
					if _, exists := image[key]; !exists {
						image[key] = val
					}
				}
			}
			// Also expose as image_info for direct access
			payload["image_info"] = result.ImageInfo
		}
	}

	meta := blockMeta{
		Ecosystem: "oci",
		Name:      info.Repository,
		Version:   info.Reference,
		Operation: info.Operation,
	}
	serveWithPolicy(w, r, h.policies, policy.EntrypointOCIArtifactRequest, payload, meta, h.proxy)
}

type ociRequestInfo struct {
	Repository string
	Reference  string
	Tag        string
	Digest     string
	Operation  string
}

func parseOCIRequestPath(path string) ociRequestInfo {
	info := ociRequestInfo{Operation: ociOperationUnknown}
	if !strings.HasPrefix(path, "/v2") {
		return info
	}
	rest := strings.TrimPrefix(path, "/v2")
	rest = strings.TrimPrefix(rest, "/")
	if rest == "" {
		info.Operation = ociOperationPing
		return info
	}
	if strings.HasPrefix(rest, "_catalog") {
		info.Operation = ociOperationCatalog
		return info
	}
	if repo, ref, ok := strings.Cut(rest, "/manifests/"); ok {
		info.Repository = strings.TrimSuffix(repo, "/")
		info.Reference = ref
		info.Operation = ociOperationManifest
		info.Tag, info.Digest = splitOCIReference(ref)
		return info
	}
	if repo, _, ok := strings.Cut(rest, "/blobs/uploads/"); ok {
		info.Repository = strings.TrimSuffix(repo, "/")
		info.Operation = ociOperationUpload
		return info
	}
	if repo, digest, ok := strings.Cut(rest, "/blobs/"); ok {
		info.Repository = strings.TrimSuffix(repo, "/")
		info.Digest = digest
		info.Reference = digest
		info.Operation = ociOperationBlob
		return info
	}
	if repo, _, ok := strings.Cut(rest, "/tags/list"); ok {
		info.Repository = strings.TrimSuffix(repo, "/")
		info.Operation = ociOperationTags
		return info
	}
	return info
}

func splitOCIReference(ref string) (string, string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", ""
	}
	if strings.HasPrefix(ref, "sha") && strings.Contains(ref, ":") {
		return "", ref
	}
	return ref, ""
}

func (h *ociHandler) buildPayload(ctx context.Context, info ociRequestInfo, path string) map[string]any {
	registry := h.registry
	reference := strings.TrimSpace(info.Reference)
	hasVersion := reference != ""
	version := reference
	rawVersion := reference
	if !hasVersion {
		version = unknownVersionPlaceholder
		rawVersion = ""
	}

	// imageBase is registry/repository without tag (e.g., "gcr.io/project/app")
	imageBase := ""
	if info.Repository != "" {
		if registry != "" {
			imageBase = registry + "/" + info.Repository
		} else {
			imageBase = info.Repository
		}
	}

	// imageRef is the full image reference including tag or digest
	// (e.g., "gcr.io/project/app:v1.2.3" or "gcr.io/project/app@sha256:...")
	imageRef := imageBase
	if imageBase != "" {
		if info.Digest != "" {
			imageRef = imageBase + "@" + info.Digest
		} else if info.Tag != "" {
			imageRef = imageBase + ":" + info.Tag
		}
	}

	req := map[string]any{
		"ecosystem":   "oci",
		"version":     version,
		"raw_version": rawVersion,
		"has_version": hasVersion,
		"operation":   info.Operation,
		"path":        path,
		"package":     info.Repository,
		"registry":    registry,
		"repository":  info.Repository,
		"reference":   reference,
		"tag":         info.Tag,
		"digest":      info.Digest,
		"image":       imageRef,
	}

	imgRef := &image.Ref{
		Registry:   registry,
		Repository: info.Repository,
		Tag:        info.Tag,
		Digest:     info.Digest,
		Reference:  reference,
		Image:      imageRef,
	}

	payload := map[string]any{
		"request": req,
		"target":  buildOCITarget(info, registry, imageBase),
		"image":   imgRef.ToMap(),
	}

	if claims := JWTClaimsFromContext(ctx); claims != nil {
		payload["jwt"] = claims.ToMap()
	} else {
		payload["jwt"] = AnonymousClaims()
	}

	return payload
}

func buildOCITarget(info ociRequestInfo, registry, imageName string) map[string]any {
	provenance := map[string]any{
		"transport":  "remote",
		"registry":   registry,
		"repository": info.Repository,
		"tag":        info.Tag,
		"digest":     info.Digest,
		"reference":  info.Reference,
		"image":      imageName,
	}
	display := imageName
	if info.Reference != "" && imageName != "" {
		if info.Digest != "" {
			display = imageName + "@" + info.Digest
		} else {
			display = imageName + ":" + info.Reference
		}
	}
	if display != "" {
		display = "oci://" + display
	}
	return map[string]any{
		"kind":       string(targets.KindContainerImage),
		"display":    display,
		"ref":        info.Reference,
		"origin":     registry,
		"provenance": provenance,
	}
}

// scanResult contains the data returned from scanImageForPolicy.
type scanResult struct {
	Vulnerabilities []map[string]any
	ImageInfo       map[string]any
	Cached          bool
	Digest          string
}

func (h *ociHandler) scanImageForPolicy(ctx context.Context, info ociRequestInfo) (scanResult, error) {
	span := trace.SpanFromContext(ctx)
	ref, err := buildOCIReference(h.registry, info)
	if err != nil {
		return scanResult{}, err
	}
	digest := info.Digest
	if digest == "" && info.Tag != "" {
		// Check digest resolution cache first to avoid repeated failed lookups
		if cached, found, wasFailed := GetCachedDigestResolution(h.digestCache, h.registry, info.Repository, info.Tag); found {
			if wasFailed {
				// Previously failed - skip resolution attempt, proceed without digest
				slog.Debug("digest resolution previously failed, skipping",
					"registry", h.registry,
					"repository", info.Repository,
					"tag", info.Tag,
				)
			} else {
				// Use cached successful resolution
				digest = cached
				slog.Debug("using cached digest resolution",
					"registry", h.registry,
					"repository", info.Repository,
					"tag", info.Tag,
					"digest", digest,
				)
			}
		} else {
			// Cache miss - perform resolution
			resolved, err := h.resolveHead(ctx, ref)
			if err != nil {
				// Log digest resolution failures at warn level - this impacts caching effectiveness.
				// Without a digest, the proxy cannot effectively cache scan results for mutable tags.
				// Operators should investigate auth errors or registry connectivity issues.
				slog.Warn("failed to resolve image digest for caching - caching will be less effective",
					"registry", h.registry,
					"repository", info.Repository,
					"tag", info.Tag,
					"error", err,
				)
				// Record the failure for observability
				RecordDigestResolutionFailure(ctx, span, h.registry, info.Repository, info.Tag, err)
				// Cache the failure to avoid repeated attempts within TTL
				CacheDigestResolutionFailure(h.digestCache, h.registry, info.Repository, info.Tag)
			} else {
				digest = resolved
				// Cache successful resolution
				CacheDigestResolution(h.digestCache, h.registry, info.Repository, info.Tag, digest)
			}
		}
	}
	cacheKey := ""
	if digest != "" {
		cacheKey = imageCacheKey(h.registry, info.Repository, digest)
	}
	if cacheKey != "" {
		if cached, ok := h.imageCache.Get(cacheKey); ok {
			RecordImageScanCacheHit(ctx, span, cacheKey)
			return scanResult{
				Vulnerabilities: cached.Vulnerabilities,
				ImageInfo:       cached.ImageInfo,
				Cached:          true,
				Digest:          digest,
			}, nil
		}
		RecordImageScanCacheMiss(ctx, span, cacheKey)
	}

	target := "oci://" + ref.Name()
	if digest != "" {
		target = "oci://" + ref.Context().Name() + "@" + digest
	}

	// Apply timeout to prevent indefinite hangs on slow networks or large images.
	// The timeout is configurable via DEPUTY_PROXY_IMAGE_SCAN_TIMEOUT.
	scanCtx, cancel := context.WithTimeout(ctx, GetImageScanTimeout())
	defer cancel()

	exec, err := h.scanner.ScanContainerImage(scanCtx, target, nil, scan.Options{})
	if err != nil {
		RecordImageScanError(ctx, span, target, err)
		return scanResult{Digest: digest}, err
	}
	defer exec.Close()

	vulns := report.FlattenResult(exec.Result)
	vulnMaps := scanVulnerabilitiesToMaps(vulns)

	// Extract ImageInfo for policy evaluation (config, metadata, history)
	var imageInfoMap map[string]any
	if exec.Result.ImageInfo != nil {
		imageInfoMap = exec.Result.ImageInfo.ToMap()
	}

	if cacheKey != "" {
		h.imageCache.Set(cacheKey, ImageScanResult{
			Vulnerabilities: vulnMaps,
			ImageInfo:       imageInfoMap,
		})
	}
	RecordImageScanSuccess(ctx, span, target, len(vulnMaps), false)
	return scanResult{
		Vulnerabilities: vulnMaps,
		ImageInfo:       imageInfoMap,
		Cached:          false,
		Digest:          digest,
	}, nil
}

func buildOCIReference(registry string, info ociRequestInfo) (name.Reference, error) {
	if registry == "" {
		return nil, fmt.Errorf("registry is required")
	}
	if strings.TrimSpace(info.Repository) == "" {
		return nil, fmt.Errorf("repository is required")
	}
	ref := strings.TrimSpace(info.Reference)
	if ref == "" {
		return nil, fmt.Errorf("reference is required")
	}
	var refStr string
	if info.Digest != "" {
		refStr = fmt.Sprintf("%s/%s@%s", registry, info.Repository, info.Digest)
	} else {
		refStr = fmt.Sprintf("%s/%s:%s", registry, info.Repository, ref)
	}
	parsed, err := name.ParseReference(refStr, name.WeakValidation)
	if err != nil {
		return nil, fmt.Errorf("parse image reference %q: %w", refStr, err)
	}
	return parsed, nil
}

func resolveRemoteDigest(ctx context.Context, ref name.Reference) (string, error) {
	if ref == nil {
		return "", fmt.Errorf("image reference is required")
	}
	// Context is required for proper cancellation and timeout handling.
	// The caller must always provide a valid context.
	if ctx == nil {
		ctx = context.Background()
	}
	opts := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithContext(ctx),
	}
	desc, err := remote.Head(ref, opts...)
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), nil
}

func scanVulnerabilitiesToMaps(vulns []report.Vulnerability) []map[string]any {
	if len(vulns) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(vulns))
	for _, v := range vulns {
		m, err := policy.StructToMap(v)
		if err != nil {
			continue
		}
		out = append(out, m)
	}
	return out
}
