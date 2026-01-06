package otel

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	// TracerName is the default tracer name for Deputy spans.
	TracerName = "github.com/picatz/deputy"
)

// StartSpan starts a new span with the given name and options.
// Returns the updated context and the span.
//
// Span lifecycle management:
//   - The caller MUST call span.End() when the operation completes (typically via defer)
//   - On success, call SetSpanOK(span) before returning nil
//   - On error, call SetSpanError(span, err) before returning the error
//
// Example:
//
//	ctx, span := otel.StartSpan(ctx, "deputy.myop")
//	defer span.End()
//
//	result, err := doWork(ctx)
//	if err != nil {
//	    otel.SetSpanError(span, err)
//	    return err
//	}
//	otel.SetSpanOK(span)
//	return nil
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return Tracer(TracerName).Start(ctx, name, opts...)
}

// SpanFromContext returns the current span from the context.
// Returns a no-op span if none is present, which is safe to use
// (all operations become no-ops).
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// SetSpanError records an error on the span and sets its status to Error.
// Safe to call with nil error (no-op). Call this on error paths before
// returning an error from a function that started a span.
func SetSpanError(span trace.Span, err error) {
	if err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// SetSpanOK sets the span status to OK.
// Call this on success paths before returning nil from a function
// that started a span. This explicitly marks the span as successful.
func SetSpanOK(span trace.Span) {
	span.SetStatus(codes.Ok, "")
}

// AddSpanEvent adds an event to the span with optional attributes.
// Use events for discrete occurrences within a span (e.g., cache hits,
// policy evaluations). For continuous data, use span attributes instead.
func AddSpanEvent(span trace.Span, name string, attrs ...attribute.KeyValue) {
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// Common attribute keys for Deputy spans.
var (
	// Command attributes
	AttrCommand      = attribute.Key("deputy.command")
	AttrSubcommand   = attribute.Key("deputy.subcommand")
	AttrTargetPath   = attribute.Key("deputy.target.path")
	AttrTargetRef    = attribute.Key("deputy.target.ref")
	AttrTargetRemote = attribute.Key("deputy.target.remote")

	// Scan attributes
	AttrEcosystem       = attribute.Key("deputy.ecosystem")
	AttrPackageCount    = attribute.Key("deputy.package.count")
	AttrVulnCount       = attribute.Key("deputy.vuln.count")
	AttrVulnCritical    = attribute.Key("deputy.vuln.critical")
	AttrVulnHigh        = attribute.Key("deputy.vuln.high")
	AttrVulnMedium      = attribute.Key("deputy.vuln.medium")
	AttrVulnLow         = attribute.Key("deputy.vuln.low")
	AttrDirectDepsOnly  = attribute.Key("deputy.direct_deps_only")
	AttrPolicyEvaluated = attribute.Key("deputy.policy.evaluated")
	AttrPolicyPassed    = attribute.Key("deputy.policy.passed")

	// OSV attributes
	AttrOSVBatchSize   = attribute.Key("deputy.osv.batch_size")
	AttrOSVCacheHit    = attribute.Key("deputy.osv.cache_hit")
	AttrOSVVulnID      = attribute.Key("deputy.osv.vuln_id")
	AttrOSVQueryType   = attribute.Key("deputy.osv.query_type")
	AttrOSVResponseLen = attribute.Key("deputy.osv.response_len")

	// Policy attributes
	AttrPolicyName       = attribute.Key("deputy.policy.name")
	AttrPolicyAction     = attribute.Key("deputy.policy.action")
	AttrPolicyEntrypoint = attribute.Key("deputy.policy.entrypoint")

	// Proxy attributes
	AttrProxyListener  = attribute.Key("deputy.proxy.listener")
	AttrProxyUpstream  = attribute.Key("deputy.proxy.upstream")
	AttrProxyPackage   = attribute.Key("deputy.proxy.package")
	AttrProxyVersion   = attribute.Key("deputy.proxy.version")
	AttrProxyOperation = attribute.Key("deputy.proxy.operation")
	AttrProxyBlocked   = attribute.Key("deputy.proxy.blocked")

	// Auth attributes
	AttrAuthMode      = attribute.Key("deputy.auth.mode")
	AttrAuthResult    = attribute.Key("deputy.auth.result")
	AttrAuthSubject   = attribute.Key("deputy.auth.subject")
	AttrAuthErrorCode = attribute.Key("deputy.auth.error_code")

	// Cache attributes
	AttrCacheType = attribute.Key("deputy.cache.type")
	AttrCacheHit  = attribute.Key("deputy.cache.hit")
	AttrCacheKey  = attribute.Key("deputy.cache.key")

	// MCP attributes
	AttrMCPTool           = attribute.Key("deputy.mcp.tool")
	AttrMCPVulnID         = attribute.Key("deputy.mcp.vuln_id")
	AttrMCPVulnCount      = attribute.Key("deputy.mcp.vuln_count")
	AttrMCPPackageCount   = attribute.Key("deputy.mcp.package_count")
	AttrMCPImage          = attribute.Key("deputy.mcp.image")
	AttrMCPBaseRef        = attribute.Key("deputy.mcp.base_ref")
	AttrMCPTargetRef      = attribute.Key("deputy.mcp.target_ref")
	AttrMCPChangeCount    = attribute.Key("deputy.mcp.change_count")
	AttrMCPTriageCount    = attribute.Key("deputy.mcp.triage_count")
	AttrMCPGraphPackage   = attribute.Key("deputy.mcp.graph_package")
	AttrMCPGraphFound     = attribute.Key("deputy.mcp.graph_found")
	AttrMCPGraphDirect    = attribute.Key("deputy.mcp.graph_direct")
	AttrMCPGraphPathCount = attribute.Key("deputy.mcp.graph_path_count")
)

// WithCommandAttrs returns span start options for command spans.
func WithCommandAttrs(command string) trace.SpanStartOption {
	return trace.WithAttributes(AttrCommand.String(command))
}

// WithTargetAttrs returns span start options for target resolution spans.
func WithTargetAttrs(path, ref string, isRemote bool) trace.SpanStartOption {
	return trace.WithAttributes(
		AttrTargetPath.String(path),
		AttrTargetRef.String(ref),
		AttrTargetRemote.Bool(isRemote),
	)
}

// WithEcosystemAttr returns a span start option for ecosystem.
func WithEcosystemAttr(ecosystem string) trace.SpanStartOption {
	return trace.WithAttributes(AttrEcosystem.String(ecosystem))
}

// WithOSVAttrs returns span start options for OSV query spans.
func WithOSVAttrs(batchSize int, queryType string) trace.SpanStartOption {
	return trace.WithAttributes(
		AttrOSVBatchSize.Int(batchSize),
		AttrOSVQueryType.String(queryType),
	)
}

// WithPolicyAttrs returns span start options for policy evaluation spans.
func WithPolicyAttrs(name, entrypoint string) trace.SpanStartOption {
	return trace.WithAttributes(
		AttrPolicyName.String(name),
		AttrPolicyEntrypoint.String(entrypoint),
	)
}

// WithProxyAttrs returns span start options for proxy request spans.
func WithProxyAttrs(listener, ecosystem, pkg, version string) trace.SpanStartOption {
	return trace.WithAttributes(
		AttrProxyListener.String(listener),
		AttrEcosystem.String(ecosystem),
		AttrProxyPackage.String(pkg),
		AttrProxyVersion.String(version),
	)
}

// RecordScanResults adds scan result attributes to a span.
func RecordScanResults(span trace.Span, pkgCount, vulnCount, critical, high, medium, low int) {
	span.SetAttributes(
		AttrPackageCount.Int(pkgCount),
		AttrVulnCount.Int(vulnCount),
		AttrVulnCritical.Int(critical),
		AttrVulnHigh.Int(high),
		AttrVulnMedium.Int(medium),
		AttrVulnLow.Int(low),
	)
}

// RecordCacheAccess adds a cache access event to a span.
func RecordCacheAccess(span trace.Span, cacheType string, hit bool, key string) {
	span.AddEvent("cache.access", trace.WithAttributes(
		AttrCacheType.String(cacheType),
		AttrCacheHit.Bool(hit),
		AttrCacheKey.String(key),
	))
}

// RecordPolicyResult adds a policy evaluation result event to a span.
// Called by the policy engine after each policy is evaluated to provide
// per-policy trace visibility. The action should be "allow", "deny", or "warn".
func RecordPolicyResult(span trace.Span, policyName, action string) {
	span.AddEvent("policy.evaluated", trace.WithAttributes(
		AttrPolicyName.String(policyName),
		AttrPolicyAction.String(action),
	))
}

// ScanCompletion holds data for recording scan completion on both traces and metrics.
// Use with RecordScanCompletion for consistent observability across both signals.
type ScanCompletion struct {
	Span         trace.Span     // The span to record attributes on
	Duration     float64        // Scan duration in seconds
	Ecosystem    string         // Package ecosystem (e.g., "go", "npm", "sbom")
	PackageCount int            // Number of packages scanned
	Severity     SeverityCounts // Vulnerability counts by severity
}

// RecordScanCompletion records scan results on both the span (trace) and metrics.
// This provides a single call to update both observability signals consistently,
// avoiding duplication and ensuring trace attributes and metrics stay in sync.
//
// Note: This does NOT call SetSpanOK - the caller should still explicitly
// mark the span status after this call.
func RecordScanCompletion(ctx context.Context, c ScanCompletion) {
	// Record on span
	RecordScanResults(c.Span, c.PackageCount, c.Severity.Total(),
		c.Severity.Critical, c.Severity.High, c.Severity.Medium, c.Severity.Low)

	// Record metrics
	RecordScanMetrics(ctx, c.Duration, c.Ecosystem, c.PackageCount, c.Severity.Total(), c.Severity.ToMap())
}
