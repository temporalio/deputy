// Package proxy provides observability instrumentation for the Deputy proxy.
//
// This file contains OpenTelemetry (OTel) integration for the proxy package,
// providing span enrichment, events, and metrics recording for proxy operations.
//
// # Attribute Naming
//
// This package reuses attribute keys from internal/otel where possible for consistency.
// Some attributes use the central package's keys (e.g., deputyotel.AttrProxyPackage),
// while proxy-specific attributes that need different semantics or don't exist in the
// central package use the `deputy.proxy.*` namespace defined locally.
//
// # Span Structure
//
// The proxy uses otelhttp middleware to create the root span for each request.
// This file provides helpers to enrich that span with proxy-specific data:
//
//	deputy.proxy.<ecosystem>                    (created by otelhttp middleware)
//	  └─ events:
//	       auth.completed                       (auth result)
//	       policy.evaluated                     (policy result)
//	       cache.access (osv/license)           (cache hits/misses)
//
// # Usage
//
// Span enrichment is done by retrieving the current span from context and
// adding attributes/events:
//
//	span := trace.SpanFromContext(ctx)
//	RecordProxyAuthResult(span, claims, nil)
//
// # Metrics
//
// Metrics are recorded via the otel package's helpers:
//
//	deputyotel.RecordProxyRequest(ctx, duration, ecosystem, statusCode)
//	deputyotel.RecordProxyAuth(ctx, "success", "")
//	deputyotel.RecordProxyPolicyDenial(ctx, ecosystem, policyName)
package proxy

import (
	"context"
	"time"

	deputyotel "github.com/temporalio/deputy/internal/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Proxy-specific span attribute keys.
//
// We use the central otel package's keys where they match (AttrProxy*, AttrCache*, AttrPolicy*).
// For proxy-specific context that differs from the central definitions, we define local keys
// with the `deputy.proxy.*` namespace.
var (
	// Request attributes - reuse from central otel package where possible
	attrProxyEcosystem  = attribute.Key("deputy.proxy.ecosystem") // Not in central (central has deputy.ecosystem)
	attrProxyPackage    = deputyotel.AttrProxyPackage             // Reuse: deputy.proxy.package
	attrProxyVersion    = deputyotel.AttrProxyVersion             // Reuse: deputy.proxy.version
	attrProxyOperation  = deputyotel.AttrProxyOperation           // Reuse: deputy.proxy.operation
	attrProxyUpstream   = deputyotel.AttrProxyUpstream            // Reuse: deputy.proxy.upstream
	attrProxyListenerID = deputyotel.AttrProxyListener            // Reuse: deputy.proxy.listener

	// Auth attributes - proxy-specific (use deputy.proxy.auth.* for proxy context)
	// The central package has deputy.auth.* for general auth context,
	// but proxy auth events are specific to request handling.
	attrAuthResult    = attribute.Key("deputy.proxy.auth.result")
	attrAuthSubject   = attribute.Key("deputy.proxy.auth.subject")
	attrAuthErrorCode = attribute.Key("deputy.proxy.auth.error_code")
	attrAuthAnonymous = attribute.Key("deputy.proxy.auth.anonymous")

	// Policy attributes - mix of central and proxy-specific
	attrPolicyName       = deputyotel.AttrPolicyName       // Reuse: deputy.policy.name
	attrPolicyEntrypoint = deputyotel.AttrPolicyEntrypoint // Reuse: deputy.policy.entrypoint
	attrPolicyResult     = attribute.Key("deputy.proxy.policy.result")
	attrPolicyReason     = attribute.Key("deputy.proxy.policy.reason")
	attrPolicyWarnings   = attribute.Key("deputy.proxy.policy.warnings")

	// Cache attributes - reuse from central otel package
	attrCacheType = deputyotel.AttrCacheType // Reuse: deputy.cache.type
	attrCacheHit  = deputyotel.AttrCacheHit  // Reuse: deputy.cache.hit
	attrCacheKey  = deputyotel.AttrCacheKey  // Reuse: deputy.cache.key

	// Vulnerability attributes - proxy-specific
	attrVulnerabilityCount = attribute.Key("deputy.proxy.vulnerability.count")
)

// AuthResult represents the outcome of an authentication attempt.
type AuthResult string

// Authentication result constants.
const (
	AuthResultSuccess   AuthResult = "success"
	AuthResultAnonymous AuthResult = "anonymous"
	AuthResultRejected  AuthResult = "rejected"
	AuthResultError     AuthResult = "error"
)

// PolicyResult represents the outcome of policy evaluation.
type PolicyResult string

// Policy result constants.
const (
	PolicyResultAllow PolicyResult = "allow"
	PolicyResultDeny  PolicyResult = "deny"
	PolicyResultWarn  PolicyResult = "warn"
	PolicyResultError PolicyResult = "error"
)

// CacheType identifies the type of cache being accessed.
type CacheType string

// Cache type constants.
const (
	CacheTypeOSV     CacheType = "osv"
	CacheTypeLicense CacheType = "license"
	CacheTypeImage   CacheType = "image_scan"
)

// RequestInfo contains information about a proxy request for span enrichment.
// This is used to add attributes to the current span.
type RequestInfo struct {
	Ecosystem  string
	Package    string
	Version    string
	Operation  string
	Listener   string
	Upstream   string
	HasVersion bool
}

// EnrichSpanWithRequest adds proxy request attributes to the current span.
// Call this early in request processing to provide context for any errors.
func EnrichSpanWithRequest(span trace.Span, info RequestInfo) {
	attrs := []attribute.KeyValue{
		attrProxyEcosystem.String(info.Ecosystem),
		attrProxyPackage.String(info.Package),
		attrProxyOperation.String(info.Operation),
	}
	if info.Listener != "" {
		attrs = append(attrs, attrProxyListenerID.String(info.Listener))
	}
	if info.Upstream != "" {
		attrs = append(attrs, attrProxyUpstream.String(info.Upstream))
	}
	if info.HasVersion && info.Version != "" {
		attrs = append(attrs, attrProxyVersion.String(info.Version))
	}
	span.SetAttributes(attrs...)
}

// AuthEventData holds data for recording an authentication event.
type AuthEventData struct {
	Result    AuthResult
	Subject   string // JWT subject claim, empty for anonymous
	ErrorCode string // Error code if auth failed
	Anonymous bool
}

// RecordAuthEvent adds an authentication event to the span and records metrics.
// Call this after authentication completes (success or failure).
func RecordAuthEvent(ctx context.Context, span trace.Span, data AuthEventData) {
	attrs := []attribute.KeyValue{
		attrAuthResult.String(string(data.Result)),
		attrAuthAnonymous.Bool(data.Anonymous),
	}
	if data.Subject != "" {
		attrs = append(attrs, attrAuthSubject.String(data.Subject))
	}
	if data.ErrorCode != "" {
		attrs = append(attrs, attrAuthErrorCode.String(data.ErrorCode))
	}

	span.AddEvent("auth.completed", trace.WithAttributes(attrs...))

	// Record metrics
	errorCode := ""
	if data.ErrorCode != "" {
		errorCode = data.ErrorCode
	}
	deputyotel.RecordProxyAuth(ctx, string(data.Result), errorCode)
}

// RecordAuthSuccess records a successful authentication event.
func RecordAuthSuccess(ctx context.Context, span trace.Span, subject string) {
	RecordAuthEvent(ctx, span, AuthEventData{
		Result:    AuthResultSuccess,
		Subject:   subject,
		Anonymous: false,
	})
}

// RecordAuthAnonymous records an anonymous request (no token provided).
func RecordAuthAnonymous(ctx context.Context, span trace.Span) {
	RecordAuthEvent(ctx, span, AuthEventData{
		Result:    AuthResultAnonymous,
		Anonymous: true,
	})
}

// RecordAuthRejected records a rejected authentication attempt.
func RecordAuthRejected(ctx context.Context, span trace.Span, errorCode string) {
	RecordAuthEvent(ctx, span, AuthEventData{
		Result:    AuthResultRejected,
		ErrorCode: errorCode,
		Anonymous: false,
	})
}

// PolicyEventData holds data for recording a policy evaluation event.
type PolicyEventData struct {
	Result       PolicyResult
	Duration     time.Duration // Time spent evaluating policy
	Entrypoint   string
	PolicyName   string // Name of the policy that caused deny/warn
	Reason       string // Reason for deny/warn
	WarningCount int
}

// RecordPolicyEvent adds a policy evaluation event to the span and records metrics.
// Call this after policy evaluation completes.
func RecordPolicyEvent(ctx context.Context, span trace.Span, data PolicyEventData) {
	attrs := []attribute.KeyValue{
		attrPolicyResult.String(string(data.Result)),
		attrPolicyEntrypoint.String(data.Entrypoint),
	}
	if data.PolicyName != "" {
		attrs = append(attrs, attrPolicyName.String(data.PolicyName))
	}
	if data.Reason != "" {
		attrs = append(attrs, attrPolicyReason.String(data.Reason))
	}
	if data.WarningCount > 0 {
		attrs = append(attrs, attrPolicyWarnings.Int(data.WarningCount))
	}

	span.AddEvent("policy.evaluated", trace.WithAttributes(attrs...))

	// Record metrics with actual duration
	deputyotel.RecordPolicyEvaluation(ctx, data.Duration.Seconds(), string(data.Result))
}

// RecordPolicyAllow records an allowed request (no deny action).
func RecordPolicyAllow(ctx context.Context, span trace.Span, entrypoint string, warningCount int, duration time.Duration) {
	RecordPolicyEvent(ctx, span, PolicyEventData{
		Result:       PolicyResultAllow,
		Duration:     duration,
		Entrypoint:   entrypoint,
		WarningCount: warningCount,
	})
}

// RecordPolicyDeny records a denied request with the denying policy info.
func RecordPolicyDeny(ctx context.Context, span trace.Span, entrypoint, policyName, reason, ecosystem string, duration time.Duration) {
	RecordPolicyEvent(ctx, span, PolicyEventData{
		Result:     PolicyResultDeny,
		Duration:   duration,
		Entrypoint: entrypoint,
		PolicyName: policyName,
		Reason:     reason,
	})

	// Record denial metric
	deputyotel.RecordProxyPolicyDenial(ctx, ecosystem, policyName)
}

// CacheEventData holds data for recording a cache access event.
type CacheEventData struct {
	Type CacheType
	Hit  bool
	Key  string // Package key for debugging
}

// RecordCacheEvent adds a cache access event to the span and records metrics.
func RecordCacheEvent(ctx context.Context, span trace.Span, data CacheEventData) {
	attrs := []attribute.KeyValue{
		attrCacheType.String(string(data.Type)),
		attrCacheHit.Bool(data.Hit),
	}
	if data.Key != "" {
		attrs = append(attrs, attrCacheKey.String(data.Key))
	}

	span.AddEvent("cache.access", trace.WithAttributes(attrs...))

	// Record OSV cache metrics specifically
	if data.Type == CacheTypeOSV {
		deputyotel.RecordOSVCacheAccess(ctx, data.Hit)
	}
}

// RecordOSVCacheHit records an OSV cache hit.
func RecordOSVCacheHit(ctx context.Context, span trace.Span, key string) {
	RecordCacheEvent(ctx, span, CacheEventData{
		Type: CacheTypeOSV,
		Hit:  true,
		Key:  key,
	})
}

// RecordOSVCacheMiss records an OSV cache miss.
func RecordOSVCacheMiss(ctx context.Context, span trace.Span, key string) {
	RecordCacheEvent(ctx, span, CacheEventData{
		Type: CacheTypeOSV,
		Hit:  false,
		Key:  key,
	})
}

// RecordLicenseCacheHit records a license cache hit.
func RecordLicenseCacheHit(ctx context.Context, span trace.Span, key string) {
	RecordCacheEvent(ctx, span, CacheEventData{
		Type: CacheTypeLicense,
		Hit:  true,
		Key:  key,
	})
}

// RecordLicenseCacheMiss records a license cache miss.
func RecordLicenseCacheMiss(ctx context.Context, span trace.Span, key string) {
	RecordCacheEvent(ctx, span, CacheEventData{
		Type: CacheTypeLicense,
		Hit:  false,
		Key:  key,
	})
}

// RecordImageScanCacheHit records an image scan cache hit.
func RecordImageScanCacheHit(ctx context.Context, span trace.Span, key string) {
	RecordCacheEvent(ctx, span, CacheEventData{
		Type: CacheTypeImage,
		Hit:  true,
		Key:  key,
	})
}

// RecordImageScanCacheMiss records an image scan cache miss.
func RecordImageScanCacheMiss(ctx context.Context, span trace.Span, key string) {
	RecordCacheEvent(ctx, span, CacheEventData{
		Type: CacheTypeImage,
		Hit:  false,
		Key:  key,
	})
}

// RecordVulnerabilityCount adds vulnerability count to the span.
// Call this when vulnerability lookup completes.
func RecordVulnerabilityCount(span trace.Span, count int) {
	span.SetAttributes(attrVulnerabilityCount.Int(count))
}

// RecordDigestResolutionFailure records when tag-to-digest resolution fails.
// This affects caching effectiveness - without a digest, each request triggers a scan.
func RecordDigestResolutionFailure(ctx context.Context, span trace.Span, registry, repository, tag string, err error) {
	attrs := []attribute.KeyValue{
		attribute.String("deputy.image.registry", registry),
		attribute.String("deputy.image.repository", repository),
		attribute.String("deputy.image.tag", tag),
	}
	if err != nil {
		attrs = append(attrs, attribute.String("error", err.Error()))
	}
	span.AddEvent("image.digest_resolution_failed", trace.WithAttributes(attrs...))
}

// RecordImageScanError records when a container image scan fails.
// This provides visibility into scan failures for debugging and alerting.
func RecordImageScanError(ctx context.Context, span trace.Span, target string, err error) {
	attrs := []attribute.KeyValue{
		attribute.String("deputy.image.target", target),
	}
	if err != nil {
		attrs = append(attrs, attribute.String("error", err.Error()))
		span.RecordError(err)
	}
	span.AddEvent("image.scan_failed", trace.WithAttributes(attrs...))
}

// RecordImageScanSuccess records when a container image scan completes successfully.
func RecordImageScanSuccess(ctx context.Context, span trace.Span, target string, vulnCount int, cached bool) {
	attrs := []attribute.KeyValue{
		attribute.String("deputy.image.target", target),
		attribute.Int("deputy.image.vulnerability_count", vulnCount),
		attribute.Bool("deputy.image.cached", cached),
	}
	span.AddEvent("image.scan_completed", trace.WithAttributes(attrs...))
}

// ProxyRequestRecorder provides a convenient way to record request metrics.
// Create one at the start of request handling and call Complete when done.
type ProxyRequestRecorder struct {
	ctx       context.Context
	startTime time.Time
	ecosystem string
}

// NewProxyRequestRecorder creates a new recorder for tracking request duration.
func NewProxyRequestRecorder(ctx context.Context, ecosystem string) *ProxyRequestRecorder {
	return &ProxyRequestRecorder{
		ctx:       ctx,
		startTime: time.Now(),
		ecosystem: ecosystem,
	}
}

// Complete records the request metrics with the given status code.
// Call this at the end of request processing (typically via defer).
func (r *ProxyRequestRecorder) Complete(statusCode int) {
	duration := time.Since(r.startTime).Seconds()
	deputyotel.RecordProxyRequest(r.ctx, duration, r.ecosystem, statusCode)
}
