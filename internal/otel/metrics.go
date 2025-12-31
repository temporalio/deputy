package otel

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	// MeterName is the default meter name for Deputy metrics.
	MeterName = "github.com/picatz/deputy"
)

// Metrics holds all Deputy metric instruments.
// Use GetMetrics() to access the singleton instance.
type Metrics struct {
	// Scan metrics
	ScanDuration      metric.Float64Histogram
	ScanPackages      metric.Int64Counter
	ScanVulns         metric.Int64Counter
	ScanPolicyResults metric.Int64Counter

	// OSV metrics
	OSVQueries       metric.Int64Counter
	OSVQueryDuration metric.Float64Histogram
	OSVCacheHits     metric.Int64Counter
	OSVCacheMisses   metric.Int64Counter

	// Policy metrics
	PolicyEvaluations metric.Int64Counter
	PolicyDuration    metric.Float64Histogram

	// Proxy metrics
	ProxyRequests       metric.Int64Counter
	ProxyRequestDuration metric.Float64Histogram
	ProxyAuth           metric.Int64Counter
	ProxyPolicyDenials  metric.Int64Counter

	// Cache metrics
	CacheHits   metric.Int64Counter
	CacheMisses metric.Int64Counter
	CacheSize   metric.Int64Gauge
}

var (
	globalMetrics    *Metrics
	metricsOnce      sync.Once
	metricsErr       error
	metricsWarnOnce  sync.Once
)

// GetMetrics returns the singleton Metrics instance.
// Creates the instruments on first call. Safe for concurrent use.
func GetMetrics() (*Metrics, error) {
	metricsOnce.Do(func() {
		globalMetrics, metricsErr = newMetrics()
		if metricsErr != nil {
			slog.Warn("failed to initialize OTel metrics instruments, metrics will not be recorded",
				"error", metricsErr)
		}
	})
	return globalMetrics, metricsErr
}

// warnMetricsUnavailable logs a warning once when metrics are unavailable.
// This prevents log spam while still alerting operators to the issue.
func warnMetricsUnavailable(operation string, err error) {
	metricsWarnOnce.Do(func() {
		slog.Warn("metrics unavailable, telemetry data will not be recorded",
			"first_operation", operation,
			"error", err)
	})
}

// getMetricsForRecording returns the metrics instance for recording.
// Returns nil if metrics are unavailable (logs warning once).
// This helper consolidates the common GetMetrics + warning pattern.
func getMetricsForRecording(operation string) *Metrics {
	m, err := GetMetrics()
	if err != nil {
		warnMetricsUnavailable(operation, err)
		return nil
	}
	return m
}

func newMetrics() (*Metrics, error) {
	m := Meter(MeterName)
	metrics := &Metrics{}

	var err error

	// Scan metrics
	metrics.ScanDuration, err = m.Float64Histogram(
		"deputy.scan.duration",
		metric.WithDescription("Duration of scan operations in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	metrics.ScanPackages, err = m.Int64Counter(
		"deputy.scan.packages",
		metric.WithDescription("Number of packages scanned"),
	)
	if err != nil {
		return nil, err
	}

	metrics.ScanVulns, err = m.Int64Counter(
		"deputy.scan.vulnerabilities",
		metric.WithDescription("Number of vulnerabilities found"),
	)
	if err != nil {
		return nil, err
	}

	metrics.ScanPolicyResults, err = m.Int64Counter(
		"deputy.scan.policy_results",
		metric.WithDescription("Policy evaluation results"),
	)
	if err != nil {
		return nil, err
	}

	// OSV metrics
	metrics.OSVQueries, err = m.Int64Counter(
		"deputy.osv.queries",
		metric.WithDescription("Number of OSV API queries"),
	)
	if err != nil {
		return nil, err
	}

	metrics.OSVQueryDuration, err = m.Float64Histogram(
		"deputy.osv.query.duration",
		metric.WithDescription("Duration of OSV queries in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	metrics.OSVCacheHits, err = m.Int64Counter(
		"deputy.osv.cache.hits",
		metric.WithDescription("Number of OSV cache hits"),
	)
	if err != nil {
		return nil, err
	}

	metrics.OSVCacheMisses, err = m.Int64Counter(
		"deputy.osv.cache.misses",
		metric.WithDescription("Number of OSV cache misses"),
	)
	if err != nil {
		return nil, err
	}

	// Policy metrics
	metrics.PolicyEvaluations, err = m.Int64Counter(
		"deputy.policy.evaluations",
		metric.WithDescription("Number of policy evaluations"),
	)
	if err != nil {
		return nil, err
	}

	metrics.PolicyDuration, err = m.Float64Histogram(
		"deputy.policy.duration",
		metric.WithDescription("Duration of policy evaluations in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	// Proxy metrics
	metrics.ProxyRequests, err = m.Int64Counter(
		"deputy.proxy.requests",
		metric.WithDescription("Number of proxy requests"),
	)
	if err != nil {
		return nil, err
	}

	metrics.ProxyRequestDuration, err = m.Float64Histogram(
		"deputy.proxy.request.duration",
		metric.WithDescription("Duration of proxy requests in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	metrics.ProxyAuth, err = m.Int64Counter(
		"deputy.proxy.auth",
		metric.WithDescription("Authentication attempts"),
	)
	if err != nil {
		return nil, err
	}

	metrics.ProxyPolicyDenials, err = m.Int64Counter(
		"deputy.proxy.policy_denials",
		metric.WithDescription("Number of requests denied by policy"),
	)
	if err != nil {
		return nil, err
	}

	// Cache metrics
	metrics.CacheHits, err = m.Int64Counter(
		"deputy.cache.hits",
		metric.WithDescription("Cache hits"),
	)
	if err != nil {
		return nil, err
	}

	metrics.CacheMisses, err = m.Int64Counter(
		"deputy.cache.misses",
		metric.WithDescription("Cache misses"),
	)
	if err != nil {
		return nil, err
	}

	metrics.CacheSize, err = m.Int64Gauge(
		"deputy.cache.size",
		metric.WithDescription("Current cache size"),
	)
	if err != nil {
		return nil, err
	}

	return metrics, nil
}

// Common attribute values for metrics.
// Note: Attribute keys use the "deputy." namespace to match trace attributes
// for cross-signal correlation. The OTel SDK automatically converts dots to
// underscores for Prometheus export (e.g., "deputy.ecosystem" -> "deputy_ecosystem").
var (
	// Ecosystem attributes - using deputy.ecosystem for consistency with traces
	AttrEcosystemGo     = attribute.String("deputy.ecosystem", "go")
	AttrEcosystemNpm    = attribute.String("deputy.ecosystem", "npm")
	AttrEcosystemPyPI   = attribute.String("deputy.ecosystem", "pypi")
	AttrEcosystemRuby   = attribute.String("deputy.ecosystem", "ruby")
	AttrEcosystemCargo  = attribute.String("deputy.ecosystem", "cargo")
	AttrEcosystemMaven  = attribute.String("deputy.ecosystem", "maven")
	AttrEcosystemNuget  = attribute.String("deputy.ecosystem", "nuget")

	// Severity attributes
	AttrSeverityCritical = attribute.String("severity", "CRITICAL")
	AttrSeverityHigh     = attribute.String("severity", "HIGH")
	AttrSeverityMedium   = attribute.String("severity", "MEDIUM")
	AttrSeverityLow      = attribute.String("severity", "LOW")
	AttrSeverityUnknown  = attribute.String("severity", "UNKNOWN")

	// Status attributes
	AttrStatusSuccess = attribute.String("status", "success")
	AttrStatusError   = attribute.String("status", "error")

	// Policy result attributes
	AttrPolicyResultAllow = attribute.String("result", "allow")
	AttrPolicyResultDeny  = attribute.String("result", "deny")
	AttrPolicyResultWarn  = attribute.String("result", "warn")

	// Auth result attributes
	AttrAuthResultSuccess   = attribute.String("result", "success")
	AttrAuthResultAnonymous = attribute.String("result", "anonymous")
	AttrAuthResultRejected  = attribute.String("result", "rejected")

	// Cache type attributes - using deputy.cache.type for consistency with trace attributes
	AttrCacheTypeOSV     = attribute.String("deputy.cache.type", "osv")
	AttrCacheTypeLicense = attribute.String("deputy.cache.type", "license")
	AttrCacheTypeDisk    = attribute.String("deputy.cache.type", "disk")
)

// EcosystemAttr returns an ecosystem attribute for the given ecosystem string.
// Uses "deputy.ecosystem" key for consistency with trace attributes.
func EcosystemAttr(ecosystem string) attribute.KeyValue {
	return attribute.String("deputy.ecosystem", ecosystem)
}

// SeverityAttr returns a severity attribute for the given severity string.
func SeverityAttr(severity string) attribute.KeyValue {
	return attribute.String("severity", severity)
}

// RecordScanMetrics records metrics for a completed scan.
func RecordScanMetrics(ctx context.Context, duration float64, ecosystem string, pkgCount, vulnCount int, severity map[string]int) {
	m := getMetricsForRecording("scan")
	if m == nil {
		return
	}

	ecoAttr := EcosystemAttr(ecosystem)

	m.ScanDuration.Record(ctx, duration, metric.WithAttributes(ecoAttr))
	m.ScanPackages.Add(ctx, int64(pkgCount), metric.WithAttributes(ecoAttr))

	// Record vulnerabilities by severity
	for sev, count := range severity {
		if count > 0 {
			m.ScanVulns.Add(ctx, int64(count), metric.WithAttributes(ecoAttr, SeverityAttr(sev)))
		}
	}
}

// RecordOSVQuery records an OSV query.
func RecordOSVQuery(ctx context.Context, duration float64, queryType string, success bool) {
	m := getMetricsForRecording("osv_query")
	if m == nil {
		return
	}

	typeAttr := attribute.String("query_type", queryType)
	var statusAttr attribute.KeyValue
	if success {
		statusAttr = AttrStatusSuccess
	} else {
		statusAttr = AttrStatusError
	}

	m.OSVQueries.Add(ctx, 1, metric.WithAttributes(typeAttr, statusAttr))
	m.OSVQueryDuration.Record(ctx, duration, metric.WithAttributes(typeAttr))
}

// RecordOSVCacheAccess records an OSV cache access.
func RecordOSVCacheAccess(ctx context.Context, hit bool) {
	m := getMetricsForRecording("osv_cache")
	if m == nil {
		return
	}

	if hit {
		m.OSVCacheHits.Add(ctx, 1, metric.WithAttributes(AttrCacheTypeOSV))
	} else {
		m.OSVCacheMisses.Add(ctx, 1, metric.WithAttributes(AttrCacheTypeOSV))
	}
}

// RecordPolicyEvaluation records a policy evaluation.
func RecordPolicyEvaluation(ctx context.Context, duration float64, result string) {
	m := getMetricsForRecording("policy_evaluation")
	if m == nil {
		return
	}

	resultAttr := attribute.String("result", result)
	m.PolicyEvaluations.Add(ctx, 1, metric.WithAttributes(resultAttr))
	m.PolicyDuration.Record(ctx, duration, metric.WithAttributes(resultAttr))
}

// RecordProxyRequest records a proxy request.
func RecordProxyRequest(ctx context.Context, duration float64, ecosystem string, statusCode int) {
	m := getMetricsForRecording("proxy_request")
	if m == nil {
		return
	}

	ecoAttr := EcosystemAttr(ecosystem)
	statusAttr := attribute.Int("status_code", statusCode)

	m.ProxyRequests.Add(ctx, 1, metric.WithAttributes(ecoAttr, statusAttr))
	m.ProxyRequestDuration.Record(ctx, duration, metric.WithAttributes(ecoAttr))
}

// RecordProxyAuth records a proxy authentication attempt.
func RecordProxyAuth(ctx context.Context, result string, errorCode string) {
	m := getMetricsForRecording("proxy_auth")
	if m == nil {
		return
	}

	attrs := []attribute.KeyValue{attribute.String("result", result)}
	if errorCode != "" {
		attrs = append(attrs, attribute.String("error_code", errorCode))
	}

	m.ProxyAuth.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordProxyPolicyDenial records a policy denial in the proxy.
func RecordProxyPolicyDenial(ctx context.Context, ecosystem, policyName string) {
	m := getMetricsForRecording("proxy_policy_denial")
	if m == nil {
		return
	}

	m.ProxyPolicyDenials.Add(ctx, 1, metric.WithAttributes(
		EcosystemAttr(ecosystem),
		attribute.String("policy", policyName),
	))
}

// SeverityCounts holds vulnerability counts by severity level.
// This provides a standard way to pass severity data to recording functions.
type SeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

// ToMap converts SeverityCounts to a map for metric recording.
func (s SeverityCounts) ToMap() map[string]int {
	return map[string]int{
		"CRITICAL": s.Critical,
		"HIGH":     s.High,
		"MEDIUM":   s.Medium,
		"LOW":      s.Low,
	}
}

// Total returns the sum of all severity counts.
func (s SeverityCounts) Total() int {
	return s.Critical + s.High + s.Medium + s.Low
}
