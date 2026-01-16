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

	// Container image scan metrics
	ImageScanDuration metric.Float64Histogram
	ImageScanPackages metric.Int64Counter
	ImageScanLayers   metric.Int64Counter

	// OSV metrics
	OSVQueries       metric.Int64Counter
	OSVQueryDuration metric.Float64Histogram
	OSVCacheHits     metric.Int64Counter
	OSVCacheMisses   metric.Int64Counter

	// Policy metrics
	PolicyEvaluations metric.Int64Counter
	PolicyDuration    metric.Float64Histogram

	// Proxy metrics
	ProxyRequests        metric.Int64Counter
	ProxyRequestDuration metric.Float64Histogram
	ProxyAuth            metric.Int64Counter
	ProxyPolicyDenials   metric.Int64Counter

	// Cache metrics
	CacheHits      metric.Int64Counter
	CacheMisses    metric.Int64Counter
	CacheEvictions metric.Int64Counter
	CacheExpired   metric.Int64Counter
	CacheSize      metric.Int64Gauge
	CacheMaxSize   metric.Int64Gauge
	CacheHitRate   metric.Float64Gauge

	// MCP metrics
	MCPToolCalls    metric.Int64Counter
	MCPToolDuration metric.Float64Histogram
	MCPToolErrors   metric.Int64Counter

	// Sandbox metrics
	SandboxExecutions       metric.Int64Counter
	SandboxExecutionDuration metric.Float64Histogram
	SandboxFilesChanged     metric.Int64Counter
	SandboxPolicyDenials    metric.Int64Counter
}

var (
	globalMetrics   *Metrics
	metricsOnce     sync.Once
	metricsErr      error
	metricsWarnOnce sync.Once
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

	// Container image scan metrics
	metrics.ImageScanDuration, err = m.Float64Histogram(
		"deputy.image.scan.duration",
		metric.WithDescription("Duration of container image scan operations in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	metrics.ImageScanPackages, err = m.Int64Counter(
		"deputy.image.scan.packages",
		metric.WithDescription("Number of packages extracted from container images"),
	)
	if err != nil {
		return nil, err
	}

	metrics.ImageScanLayers, err = m.Int64Counter(
		"deputy.image.scan.layers",
		metric.WithDescription("Number of container image layers scanned"),
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
		metric.WithDescription("Total cache hits"),
	)
	if err != nil {
		return nil, err
	}

	metrics.CacheMisses, err = m.Int64Counter(
		"deputy.cache.misses",
		metric.WithDescription("Total cache misses"),
	)
	if err != nil {
		return nil, err
	}

	metrics.CacheEvictions, err = m.Int64Counter(
		"deputy.cache.evictions",
		metric.WithDescription("Total cache evictions due to capacity"),
	)
	if err != nil {
		return nil, err
	}

	metrics.CacheExpired, err = m.Int64Counter(
		"deputy.cache.expired",
		metric.WithDescription("Total cache entries expired due to TTL"),
	)
	if err != nil {
		return nil, err
	}

	metrics.CacheSize, err = m.Int64Gauge(
		"deputy.cache.size",
		metric.WithDescription("Current number of entries in cache"),
	)
	if err != nil {
		return nil, err
	}

	metrics.CacheMaxSize, err = m.Int64Gauge(
		"deputy.cache.max_size",
		metric.WithDescription("Maximum cache capacity"),
	)
	if err != nil {
		return nil, err
	}

	metrics.CacheHitRate, err = m.Float64Gauge(
		"deputy.cache.hit_rate",
		metric.WithDescription("Cache hit rate (0.0-1.0)"),
	)
	if err != nil {
		return nil, err
	}

	// MCP metrics
	metrics.MCPToolCalls, err = m.Int64Counter(
		"deputy.mcp.tool_calls",
		metric.WithDescription("Number of MCP tool invocations"),
	)
	if err != nil {
		return nil, err
	}

	metrics.MCPToolDuration, err = m.Float64Histogram(
		"deputy.mcp.tool_duration",
		metric.WithDescription("Duration of MCP tool invocations in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	metrics.MCPToolErrors, err = m.Int64Counter(
		"deputy.mcp.tool_errors",
		metric.WithDescription("Number of MCP tool errors"),
	)
	if err != nil {
		return nil, err
	}

	// Sandbox metrics
	metrics.SandboxExecutions, err = m.Int64Counter(
		"deputy.sandbox.executions",
		metric.WithDescription("Number of sandbox executions"),
	)
	if err != nil {
		return nil, err
	}

	metrics.SandboxExecutionDuration, err = m.Float64Histogram(
		"deputy.sandbox.execution.duration",
		metric.WithDescription("Duration of sandbox executions in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, err
	}

	metrics.SandboxFilesChanged, err = m.Int64Counter(
		"deputy.sandbox.files_changed",
		metric.WithDescription("Number of files changed during sandbox execution"),
	)
	if err != nil {
		return nil, err
	}

	metrics.SandboxPolicyDenials, err = m.Int64Counter(
		"deputy.sandbox.policy_denials",
		metric.WithDescription("Number of sandbox executions denied by policy"),
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
	AttrEcosystemGo    = attribute.String("deputy.ecosystem", "go")
	AttrEcosystemNpm   = attribute.String("deputy.ecosystem", "npm")
	AttrEcosystemPyPI  = attribute.String("deputy.ecosystem", "pypi")
	AttrEcosystemRuby  = attribute.String("deputy.ecosystem", "ruby")
	AttrEcosystemCargo = attribute.String("deputy.ecosystem", "cargo")
	AttrEcosystemMaven = attribute.String("deputy.ecosystem", "maven")
	AttrEcosystemNuget = attribute.String("deputy.ecosystem", "nuget")

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
	AttrCacheTypeOSV      = attribute.String("deputy.cache.type", "osv")
	AttrCacheTypeKEV      = attribute.String("deputy.cache.type", "kev")
	AttrCacheTypeEPSS     = attribute.String("deputy.cache.type", "epss")
	AttrCacheTypeLicense  = attribute.String("deputy.cache.type", "license")
	AttrCacheTypeDisk     = attribute.String("deputy.cache.type", "disk")
	AttrCacheTypeImage    = attribute.String("deputy.cache.type", "image_scan")
	AttrCacheTypeDepsDev  = attribute.String("deputy.cache.type", "depsdev")
	AttrCacheTypeGoProxy  = attribute.String("deputy.cache.type", "goproxy")
	AttrCacheTypeGraph    = attribute.String("deputy.cache.type", "graph")
	AttrCacheTypeGit      = attribute.String("deputy.cache.type", "git")

	// Image transport attributes for container image scans
	AttrImageTransportRemote    = attribute.String("deputy.image.transport", "remote")
	AttrImageTransportDaemon    = attribute.String("deputy.image.transport", "docker-daemon")
	AttrImageTransportTarball   = attribute.String("deputy.image.transport", "tarball")
	AttrImageTransportOCILayout = attribute.String("deputy.image.transport", "oci-layout")

	// Sandbox runtime attributes
	AttrSandboxRuntimeNone       = attribute.String("deputy.sandbox.runtime", "none")
	AttrSandboxRuntimeDocker     = attribute.String("deputy.sandbox.runtime", "docker")
	AttrSandboxRuntimeGVisor     = attribute.String("deputy.sandbox.runtime", "gvisor")
	AttrSandboxRuntimeSandboxExec = attribute.String("deputy.sandbox.runtime", "sandbox-exec")
	AttrSandboxRuntimePlugin     = attribute.String("deputy.sandbox.runtime", "plugin")

	// Sandbox network mode attributes
	AttrSandboxNetworkNone      = attribute.String("deputy.sandbox.network_mode", "none")
	AttrSandboxNetworkHost      = attribute.String("deputy.sandbox.network_mode", "host")
	AttrSandboxNetworkBridge    = attribute.String("deputy.sandbox.network_mode", "bridge")
	AttrSandboxNetworkAllowlist = attribute.String("deputy.sandbox.network_mode", "allowlist")

	// Sandbox workspace isolation attributes
	AttrSandboxIsolationDirect   = attribute.String("deputy.sandbox.workspace_isolation", "direct")
	AttrSandboxIsolationOverlay  = attribute.String("deputy.sandbox.workspace_isolation", "overlay")
	AttrSandboxIsolationSnapshot = attribute.String("deputy.sandbox.workspace_isolation", "snapshot")
	AttrSandboxIsolationTmpfs    = attribute.String("deputy.sandbox.workspace_isolation", "tmpfs")
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

// RecordImageScanMetrics records metrics for a completed container image scan.
func RecordImageScanMetrics(ctx context.Context, duration float64, transport string, registry string, pkgCount, layerCount int) {
	m := getMetricsForRecording("image_scan")
	if m == nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String("deputy.image.transport", transport),
	}
	if registry != "" {
		attrs = append(attrs, attribute.String("deputy.image.registry", registry))
	}

	m.ImageScanDuration.Record(ctx, duration, metric.WithAttributes(attrs...))
	m.ImageScanPackages.Add(ctx, int64(pkgCount), metric.WithAttributes(attrs...))
	if layerCount > 0 {
		m.ImageScanLayers.Add(ctx, int64(layerCount), metric.WithAttributes(attrs...))
	}
}

// ImageTransportAttr returns an image transport attribute for the given transport string.
func ImageTransportAttr(transport string) attribute.KeyValue {
	return attribute.String("deputy.image.transport", transport)
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

// CacheStats represents a snapshot of cache statistics compatible with
// memory.Stats from the cache/memory package.
type CacheStats struct {
	Hits     uint64  // Total cache hits
	Misses   uint64  // Total cache misses
	Evicted  uint64  // Total evictions due to capacity
	Expired  uint64  // Total expirations due to TTL
	Size     int     // Current number of entries
	MaxSize  int     // Maximum capacity
	HitRate  float64 // Hit rate (0.0-1.0)
}

// CacheTypeAttr returns a cache type attribute for the given cache name.
func CacheTypeAttr(cacheType string) attribute.KeyValue {
	return attribute.String("deputy.cache.type", cacheType)
}

// RecordCacheStats records cache statistics for a named cache.
// The cacheType parameter should identify the cache (e.g., "depsdev", "goproxy", "osv").
// Use this function with stats from memory.TTLCache.Stats().
func RecordCacheStats(ctx context.Context, cacheType string, stats CacheStats) {
	m := getMetricsForRecording("cache_stats")
	if m == nil {
		return
	}

	typeAttr := CacheTypeAttr(cacheType)

	// Record current values as gauges
	m.CacheSize.Record(ctx, int64(stats.Size), metric.WithAttributes(typeAttr))
	m.CacheMaxSize.Record(ctx, int64(stats.MaxSize), metric.WithAttributes(typeAttr))
	m.CacheHitRate.Record(ctx, stats.HitRate, metric.WithAttributes(typeAttr))
}

// RecordCacheHit records a single cache hit event.
func RecordCacheHit(ctx context.Context, cacheType string) {
	m := getMetricsForRecording("cache_hit")
	if m == nil {
		return
	}
	m.CacheHits.Add(ctx, 1, metric.WithAttributes(CacheTypeAttr(cacheType)))
}

// RecordCacheMiss records a single cache miss event.
func RecordCacheMiss(ctx context.Context, cacheType string) {
	m := getMetricsForRecording("cache_miss")
	if m == nil {
		return
	}
	m.CacheMisses.Add(ctx, 1, metric.WithAttributes(CacheTypeAttr(cacheType)))
}

// RecordCacheEviction records a single cache eviction event.
func RecordCacheEviction(ctx context.Context, cacheType string) {
	m := getMetricsForRecording("cache_eviction")
	if m == nil {
		return
	}
	m.CacheEvictions.Add(ctx, 1, metric.WithAttributes(CacheTypeAttr(cacheType)))
}

// RecordCacheExpiration records a single cache expiration event.
func RecordCacheExpiration(ctx context.Context, cacheType string) {
	m := getMetricsForRecording("cache_expiration")
	if m == nil {
		return
	}
	m.CacheExpired.Add(ctx, 1, metric.WithAttributes(CacheTypeAttr(cacheType)))
}

// RecordMCPToolCall records an MCP tool invocation.
func RecordMCPToolCall(ctx context.Context, toolName string, duration float64, success bool) {
	m := getMetricsForRecording("mcp_tool_call")
	if m == nil {
		return
	}

	toolAttr := attribute.String("deputy.mcp.tool", toolName)

	m.MCPToolCalls.Add(ctx, 1, metric.WithAttributes(toolAttr))
	m.MCPToolDuration.Record(ctx, duration, metric.WithAttributes(toolAttr))

	if !success {
		m.MCPToolErrors.Add(ctx, 1, metric.WithAttributes(toolAttr))
	}
}

// SandboxExecutionInfo holds information about a sandbox execution for metrics recording.
type SandboxExecutionInfo struct {
	Runtime            string  // Runtime name (e.g., "plugin", "docker", "gvisor")
	PluginName         string  // Plugin name if runtime is "plugin"
	NetworkMode        string  // Network mode (e.g., "none", "host", "allowlist")
	WorkspaceIsolation string  // Workspace isolation mode (e.g., "direct", "overlay")
	Duration           float64 // Execution duration in seconds
	ExitCode           int32   // Exit code from the execution
	FilesAdded         int     // Number of files added
	FilesModified      int     // Number of files modified
	FilesDeleted       int     // Number of files deleted
	Success            bool    // Whether execution succeeded
}

// SandboxRuntimeAttr returns a sandbox runtime attribute.
func SandboxRuntimeAttr(runtime string) attribute.KeyValue {
	return attribute.String("deputy.sandbox.runtime", runtime)
}

// SandboxPluginAttr returns a sandbox plugin name attribute.
func SandboxPluginAttr(pluginName string) attribute.KeyValue {
	return attribute.String("deputy.sandbox.plugin", pluginName)
}

// SandboxNetworkModeAttr returns a sandbox network mode attribute.
func SandboxNetworkModeAttr(mode string) attribute.KeyValue {
	return attribute.String("deputy.sandbox.network_mode", mode)
}

// SandboxWorkspaceIsolationAttr returns a sandbox workspace isolation attribute.
func SandboxWorkspaceIsolationAttr(isolation string) attribute.KeyValue {
	return attribute.String("deputy.sandbox.workspace_isolation", isolation)
}

// RecordSandboxExecution records metrics for a completed sandbox execution.
func RecordSandboxExecution(ctx context.Context, info SandboxExecutionInfo) {
	m := getMetricsForRecording("sandbox_execution")
	if m == nil {
		return
	}

	attrs := []attribute.KeyValue{
		SandboxRuntimeAttr(info.Runtime),
	}

	if info.PluginName != "" {
		attrs = append(attrs, SandboxPluginAttr(info.PluginName))
	}
	if info.NetworkMode != "" {
		attrs = append(attrs, SandboxNetworkModeAttr(info.NetworkMode))
	}
	if info.WorkspaceIsolation != "" {
		attrs = append(attrs, SandboxWorkspaceIsolationAttr(info.WorkspaceIsolation))
	}

	// Record success/failure
	if info.Success {
		attrs = append(attrs, AttrStatusSuccess)
	} else {
		attrs = append(attrs, AttrStatusError)
	}

	// Record exit code as attribute for correlation
	attrs = append(attrs, attribute.Int("deputy.sandbox.exit_code", int(info.ExitCode)))

	m.SandboxExecutions.Add(ctx, 1, metric.WithAttributes(attrs...))
	m.SandboxExecutionDuration.Record(ctx, info.Duration, metric.WithAttributes(attrs...))

	// Record file changes
	totalChanges := info.FilesAdded + info.FilesModified + info.FilesDeleted
	if totalChanges > 0 {
		changeAttrs := []attribute.KeyValue{
			SandboxRuntimeAttr(info.Runtime),
		}
		if info.PluginName != "" {
			changeAttrs = append(changeAttrs, SandboxPluginAttr(info.PluginName))
		}

		// Record by change type
		if info.FilesAdded > 0 {
			m.SandboxFilesChanged.Add(ctx, int64(info.FilesAdded),
				metric.WithAttributes(append(changeAttrs, attribute.String("change_type", "added"))...))
		}
		if info.FilesModified > 0 {
			m.SandboxFilesChanged.Add(ctx, int64(info.FilesModified),
				metric.WithAttributes(append(changeAttrs, attribute.String("change_type", "modified"))...))
		}
		if info.FilesDeleted > 0 {
			m.SandboxFilesChanged.Add(ctx, int64(info.FilesDeleted),
				metric.WithAttributes(append(changeAttrs, attribute.String("change_type", "deleted"))...))
		}
	}
}

// RecordSandboxPolicyDenial records a sandbox execution denied by policy.
func RecordSandboxPolicyDenial(ctx context.Context, runtime, policyName string) {
	m := getMetricsForRecording("sandbox_policy_denial")
	if m == nil {
		return
	}

	m.SandboxPolicyDenials.Add(ctx, 1, metric.WithAttributes(
		SandboxRuntimeAttr(runtime),
		attribute.String("policy", policyName),
	))
}
