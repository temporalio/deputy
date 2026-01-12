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
	"github.com/picatz/deputy/internal/scanning"
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
	imageCache   ImageScanCache
	digestCache  DigestResolutionCache
	scanner      imageScanner
	resolveHead  func(context.Context, name.Reference) (string, error)
	ociConfig    *OCIConfig
	listenerName string   // for cache scoping
	policyPaths  []string // for cache scoping
}

type imageScanner interface {
	ScanContainerImage(context.Context, string, map[string]string, scanning.Options) (*scanning.Execution, error)
}

type ociHandler struct {
	policies    PolicyEvaluator
	proxy       *httputil.ReverseProxy
	scanner     imageScanner
	imageCache  ImageScanCache
	digestCache DigestResolutionCache
	resolveHead func(context.Context, name.Reference) (string, error)
	registry    string
	ociConfig   *OCIConfig
}

// NewOCIHandler creates a handler for OCI registry proxying with policy evaluation.
func NewOCIHandler(upstream string, policies PolicyEvaluator) (http.Handler, error) {
	return newOCIHandler(upstream, policies, nil)
}

// NewOCIHandlerWithConfig creates a handler with explicit OCI configuration.
func NewOCIHandlerWithConfig(upstream string, policies PolicyEvaluator, cfg *OCIConfig) (http.Handler, error) {
	return newOCIHandler(upstream, policies, &ociHandlerOptions{ociConfig: cfg})
}

// OCIHandlerOptions configures an OCI proxy handler.
type OCIHandlerOptions struct {
	// Config is the OCI-specific configuration.
	Config *OCIConfig
	// ListenerName is the name of the listener, used for cache scoping.
	ListenerName string
	// PolicyPaths are the policy files, used to compute a hash for cache scoping.
	PolicyPaths []string
}

// NewOCIHandlerWithOptions creates a handler with full options support.
// This is the preferred constructor for production use as it enables cache scoping.
func NewOCIHandlerWithOptions(upstream string, policies PolicyEvaluator, opts *OCIHandlerOptions) (http.Handler, error) {
	if opts == nil {
		return newOCIHandler(upstream, policies, nil)
	}
	return newOCIHandler(upstream, policies, &ociHandlerOptions{
		ociConfig:    opts.Config,
		listenerName: opts.ListenerName,
		policyPaths:  opts.PolicyPaths,
	})
}

func newOCIHandler(upstream string, policies PolicyEvaluator, opts *ociHandlerOptions) (http.Handler, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parse upstream %q: %w", upstream, err)
	}
	var scanner imageScanner = defaultImageScanner{}
	imgCache := getImageScanCache(nil)
	digCache := getDigestResolutionCache(nil)
	resolveHead := resolveRemoteDigest
	var ociCfg *OCIConfig
	if opts != nil {
		if opts.scanner != nil {
			scanner = opts.scanner
		}
		if opts.resolveHead != nil {
			resolveHead = opts.resolveHead
		}
		ociCfg = opts.ociConfig

		// Build cache scope from listener/policy configuration.
		// Tenant ID is added dynamically per-request via request context.
		baseScope := CacheScope{
			ListenerName: opts.listenerName,
			PolicyHash:   HashPolicyPaths(opts.policyPaths),
		}

		// Apply scoping to image and digest caches
		// Use RequestScoped*Cache for per-request tenant isolation (via JWT claims)
		if opts.imageCache != nil {
			imgCache = NewRequestScopedImageScanCache(baseScope, getImageScanCache(opts.imageCache))
		} else if !baseScope.IsEmpty() {
			imgCache = NewRequestScopedImageScanCache(baseScope, defaultImageScanCache)
		}

		if opts.digestCache != nil {
			digCache = NewRequestScopedDigestResolutionCache(baseScope, getDigestResolutionCache(opts.digestCache))
		} else if !baseScope.IsEmpty() {
			digCache = NewRequestScopedDigestResolutionCache(baseScope, defaultDigestResolutionCache)
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
		ociConfig:   ociCfg,
	}, nil
}

func (h *ociHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := parseOCIRequestPath(r.URL.Path)
	payload := h.buildPayload(r.Context(), info, r.URL.Path)

	var pinnedDigest string

	if info.Operation == ociOperationManifest && info.Repository != "" && info.Reference != "" {
		result, scanErr := h.scanImageForPolicy(r.Context(), info)
		if result.Vulnerabilities != nil {
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
			pinnedDigest = result.Digest
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

		// TOCTOU mitigation: check mutable tag policy before proceeding
		if info.Tag != "" && info.Digest == "" {
			if err := checkMutableTagPolicy(h.ociConfig, info.Tag, info.Repository, pinnedDigest); err != nil {
				// Block the request due to mutable tag policy violation
				w.Header().Set(HeaderMutableTagBlocked, "true")
				w.Header().Set("X-Deputy-Ecosystem", "oci")
				w.Header().Set("X-Deputy-Package", info.Repository)
				w.Header().Set("X-Deputy-Version", info.Tag)
				http.Error(w, err.Error(), http.StatusForbidden)
				slog.Warn("mutable tag blocked",
					"registry", h.registry,
					"repository", info.Repository,
					"tag", info.Tag,
					"error", err,
				)
				return
			}
		}
	}

	meta := blockMeta{
		Ecosystem: "oci",
		Name:      info.Repository,
		Version:   info.Reference,
		Operation: info.Operation,
	}

	// Determine which proxy to use based on digest pinning configuration
	var upstream http.Handler = h.proxy

	// If we have a pinned digest and pinning is enabled, use the digest-pinning proxy
	if pinnedDigest != "" && info.Tag != "" && info.Digest == "" {
		if h.ociConfig.EffectivePinDigests() {
			pinnedProxy := newDigestPinningProxy(h.proxy, h.registry, h.ociConfig)
			upstream = pinnedProxy.withPinnedInfo(&pinnedRequestInfo{
				OriginalTag:  info.Tag,
				PinnedDigest: pinnedDigest,
				Repository:   info.Repository,
			})
			slog.Debug("using pinned digest for upstream request",
				"registry", h.registry,
				"repository", info.Repository,
				"tag", info.Tag,
				"digest", pinnedDigest,
			)
		}
	}

	serveWithPolicy(w, r, h.policies, policy.EntrypointOCIArtifactRequest, payload, meta, upstream)
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
	// Vulnerabilities holds proto Finding messages for policy evaluation.
	Vulnerabilities any
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
		// Use context-aware operations for tenant isolation if available
		if cached, found, wasFailed := GetCachedDigestResolutionWithContext(ctx, h.digestCache, h.registry, info.Repository, info.Tag); found {
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
				// Cache the failure to avoid repeated attempts within TTL (with tenant isolation)
				CacheDigestResolutionFailureWithContext(ctx, h.digestCache, h.registry, info.Repository, info.Tag)
			} else {
				digest = resolved
				// Cache successful resolution (with tenant isolation)
				CacheDigestResolutionWithContext(ctx, h.digestCache, h.registry, info.Repository, info.Tag, digest)
			}
		}
	}
	cacheKey := ""
	if digest != "" {
		cacheKey = imageCacheKey(h.registry, info.Repository, digest)
	}
	if cacheKey != "" {
		// Use context-aware cache operations if available (for tenant isolation)
		var cached ImageScanResult
		var ok bool
		if ctxCache, isCtxAware := h.imageCache.(ContextAwareImageScanCache); isCtxAware {
			cached, ok = ctxCache.GetWithContext(ctx, cacheKey)
		} else {
			cached, ok = h.imageCache.Get(cacheKey)
		}
		if ok {
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

	exec, err := h.scanner.ScanContainerImage(scanCtx, target, nil, scanning.Options{})
	if err != nil {
		RecordImageScanError(ctx, span, target, err)
		return scanResult{Digest: digest}, err
	}
	defer exec.Close()

	vulns := report.FlattenScanningResult(exec.Result)
	findings := scanVulnerabilitiesToFindings(vulns)

	// Extract ImageInfo for policy evaluation (config, metadata, history)
	var imageInfoMap map[string]any
	if exec.Result.ImageInfo != nil {
		imageInfoMap = exec.Result.ImageInfo.ToMap()
	}

	if cacheKey != "" {
		// Use context-aware cache operations if available (for tenant isolation)
		cacheValue := ImageScanResult{
			Vulnerabilities: findings,
			ImageInfo:       imageInfoMap,
		}
		if ctxCache, isCtxAware := h.imageCache.(ContextAwareImageScanCache); isCtxAware {
			ctxCache.SetWithContext(ctx, cacheKey, cacheValue)
		} else {
			h.imageCache.Set(cacheKey, cacheValue)
		}
	}
	RecordImageScanSuccess(ctx, span, target, len(vulns), false)
	return scanResult{
		Vulnerabilities: findings,
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

// scanVulnerabilitiesToFindings converts scan vulnerabilities to proto Finding messages.
func scanVulnerabilitiesToFindings(vulns []report.Vulnerability) any {
	findings := report.VulnerabilitiesToFindings(vulns)
	if len(findings) == 0 {
		return nil
	}
	return findings
}

// defaultImageScanner implements imageScanner using the scanning package.
type defaultImageScanner struct{}

func (defaultImageScanner) ScanContainerImage(ctx context.Context, target string, targetOpts map[string]string, opts scanning.Options) (*scanning.Execution, error) {
	return scanning.ScanContainerImage(ctx, target, targetOpts, opts)
}
