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
	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	policyv1 "github.com/picatz/deputy/gen/deputy/policy/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/container/image"
	"github.com/picatz/deputy/internal/policy"
	"github.com/picatz/deputy/internal/proto"
	"github.com/picatz/deputy/internal/report"
	"github.com/picatz/deputy/internal/scanning"
	"github.com/picatz/deputy/internal/targets"
	"go.opentelemetry.io/otel/trace"
	goproto "google.golang.org/protobuf/proto"
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
	ScanContainerImage(context.Context, string, *targets.OpenOptions, scanning.Options) (*scanning.Execution, error)
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
	ctx := r.Context()
	info := parseOCIRequestPath(r.URL.Path)

	// Collect data for policy input
	var vulns []*vulnerabilityv1.Finding
	var imageInfo *image.Info
	var pinnedDigest string

	if info.Operation == ociOperationManifest && info.Repository != "" && info.Reference != "" {
		result, _ := h.scanImageForPolicy(ctx, info)
		if result.Vulnerabilities != nil {
			// Type assert the vulnerabilities
			if findings, ok := result.Vulnerabilities.([]*vulnerabilityv1.Finding); ok {
				vulns = findings
			}
		}
		if result.Digest != "" {
			pinnedDigest = result.Digest
		}
		// Convert ImageInfo map back to struct if needed
		// The scanning result has the original ImageInfo in exec.Result.ImageInfo
		// For now, we'll build the proto ImageInfo directly from the map
		if result.ImageInfo != nil {
			// Store the map for use when building proto
			imageInfo = imageInfoFromMap(result.ImageInfo)
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

	// Build the policy input proto
	input := h.buildPolicyInput(ctx, info, vulns, imageInfo, pinnedDigest)

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

	serveWithPolicy(w, r, h.policies, policy.EntrypointOCIArtifactRequest, input, meta, upstream)
}

// buildPolicyInput constructs the OciArtifactRequestPolicyInput proto.
func (h *ociHandler) buildPolicyInput(ctx context.Context, info ociRequestInfo, vulns []*vulnerabilityv1.Finding, imgInfo *image.Info, pinnedDigest string) goproto.Message {
	reference := strings.TrimSpace(info.Reference)
	version := reference
	if reference == "" {
		version = unknownVersionPlaceholder
	}

	// Use pinned digest if available, otherwise use what we have
	digest := info.Digest
	if pinnedDigest != "" {
		digest = pinnedDigest
	}

	// Build the request proto
	req := &policyv1.ProxyRequest{
		Ecosystem: "oci",
		Version:   version,
		Operation: info.Operation,
		Package:   info.Repository,
	}

	// Get JWT claims
	jwt := jwtClaimsToProto(JWTClaimsFromContext(ctx))

	// Get environment
	env := &policyv1.Environment{
		Command:    "proxy",
		Entrypoint: policy.EntrypointOCIArtifactRequest.String(),
	}

	// Build full image reference string for policy expressions
	var fullImageRef string
	if info.Tag != "" {
		fullImageRef = h.registry + "/" + info.Repository + ":" + info.Tag
	} else if digest != "" {
		fullImageRef = h.registry + "/" + info.Repository + "@" + digest
	} else {
		fullImageRef = h.registry + "/" + info.Repository
	}

	// Build image info proto
	var imageInfoProto *containerv1.ImageInfo
	if imgInfo != nil {
		imageInfoProto = proto.ImageInfoToContainerProto(imgInfo)
	} else {
		// Create minimal image info with reference data
		imageInfoProto = &containerv1.ImageInfo{
			Metadata: &containerv1.ImageMetadata{
				Digest: digest,
			},
		}
	}
	// Set provenance fields for policy expressions
	imageInfoProto.Image = fullImageRef
	imageInfoProto.Registry = h.registry
	imageInfoProto.Repository = info.Repository
	imageInfoProto.Tag = info.Tag

	return &policyv1.OciArtifactRequestPolicyInput{
		Request:         req,
		Jwt:             jwt,
		Env:             env,
		Vulnerabilities: vulns,
		Image:           imageInfoProto,
	}
}

// imageInfoFromMap converts an ImageInfo map back to the struct.
// This is a best-effort conversion for cached data.
func imageInfoFromMap(m map[string]any) *image.Info {
	if m == nil {
		return nil
	}
	// For cached results stored as maps, we can't fully reconstruct.
	// Return nil to indicate no structured ImageInfo is available.
	// The proto will be built with minimal metadata.
	return nil
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

func (defaultImageScanner) ScanContainerImage(ctx context.Context, target string, targetOpts *targets.OpenOptions, opts scanning.Options) (*scanning.Execution, error) {
	return scanning.ScanContainerImage(ctx, target, targetOpts, opts)
}
