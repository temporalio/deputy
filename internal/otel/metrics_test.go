package otel

import (
	"context"
	"sync"
	"testing"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

func TestGetMetrics_ReturnsSameInstance(t *testing.T) {
	// Reset metrics state
	resetGlobalProvider()

	m1, err := GetMetrics()
	if err != nil {
		t.Fatalf("first GetMetrics failed: %v", err)
	}
	if m1 == nil {
		t.Fatal("first GetMetrics returned nil")
	}

	m2, err := GetMetrics()
	if err != nil {
		t.Fatalf("second GetMetrics failed: %v", err)
	}
	if m2 == nil {
		t.Fatal("second GetMetrics returned nil")
	}

	if m1 != m2 {
		t.Error("expected same Metrics instance from multiple calls")
	}
}

func TestMetrics_InstrumentsInitialized(t *testing.T) {
	resetGlobalProvider()

	m, err := GetMetrics()
	if err != nil {
		t.Fatalf("GetMetrics failed: %v", err)
	}

	// Verify all instruments are non-nil
	checks := []struct {
		name       string
		instrument any
	}{
		{"ScanDuration", m.ScanDuration},
		{"ScanPackages", m.ScanPackages},
		{"ScanVulns", m.ScanVulns},
		{"ScanPolicyResults", m.ScanPolicyResults},
		{"OSVQueries", m.OSVQueries},
		{"OSVQueryDuration", m.OSVQueryDuration},
		{"OSVCacheHits", m.OSVCacheHits},
		{"OSVCacheMisses", m.OSVCacheMisses},
		{"PolicyEvaluations", m.PolicyEvaluations},
		{"PolicyDuration", m.PolicyDuration},
		{"ProxyRequests", m.ProxyRequests},
		{"ProxyRequestDuration", m.ProxyRequestDuration},
		{"ProxyAuth", m.ProxyAuth},
		{"ProxyPolicyDenials", m.ProxyPolicyDenials},
		{"CacheHits", m.CacheHits},
		{"CacheMisses", m.CacheMisses},
		{"CacheEvictions", m.CacheEvictions},
		{"CacheExpired", m.CacheExpired},
		{"CacheSize", m.CacheSize},
		{"CacheMaxSize", m.CacheMaxSize},
		{"CacheHitRate", m.CacheHitRate},
	}

	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if c.instrument == nil {
				t.Errorf("%s is nil", c.name)
			}
		})
	}
}

func TestEcosystemAttr(t *testing.T) {
	attr := EcosystemAttr("npm")
	if string(attr.Key) != "deputy.ecosystem" {
		t.Errorf("expected key 'deputy.ecosystem', got %q", attr.Key)
	}
	if attr.Value.AsString() != "npm" {
		t.Errorf("expected value 'npm', got %q", attr.Value.AsString())
	}
}

func TestSeverityAttr(t *testing.T) {
	attr := SeverityAttr("CRITICAL")
	if string(attr.Key) != "severity" {
		t.Errorf("expected key 'severity', got %q", attr.Key)
	}
	if attr.Value.AsString() != "CRITICAL" {
		t.Errorf("expected value 'CRITICAL', got %q", attr.Value.AsString())
	}
}

func TestRecordScanMetrics_DoesNotPanic(t *testing.T) {
	ctx := context.Background()
	severity := map[string]int{
		"CRITICAL": 1,
		"HIGH":     2,
		"MEDIUM":   3,
		"LOW":      4,
	}

	// Should not panic even with no collector
	RecordScanMetrics(ctx, 1.5, "go", 100, 10, severity)
}

// setupTestMeterProvider creates a meter provider with a manual reader for testing.
// Returns the reader and a cleanup function.
func setupTestMeterProvider(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	// Set as global provider
	otel.SetMeterProvider(provider)

	// Reset the metrics singleton so it uses the new provider
	metricsOnce = sync.Once{}
	globalMetrics = nil
	metricsErr = nil
	metricsWarnOnce = sync.Once{}

	t.Cleanup(func() {
		provider.Shutdown(context.Background())
		resetGlobalProvider()
	})

	return reader
}

// findMetric searches for a metric by name in the resource metrics.
func findMetric(rm *metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

func TestRecordScanMetrics_RecordsValues(t *testing.T) {
	reader := setupTestMeterProvider(t)
	ctx := context.Background()

	severity := map[string]int{
		"CRITICAL": 2,
		"HIGH":     5,
	}

	RecordScanMetrics(ctx, 1.5, "go", 100, 7, severity)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("failed to collect metrics: %v", err)
	}

	// Verify scan duration was recorded
	durationMetric := findMetric(&rm, "deputy.scan.duration")
	if durationMetric == nil {
		t.Error("expected deputy.scan.duration metric to be recorded")
	} else {
		hist, ok := durationMetric.Data.(metricdata.Histogram[float64])
		if !ok {
			t.Errorf("expected Histogram data, got %T", durationMetric.Data)
		} else if len(hist.DataPoints) == 0 {
			t.Error("expected at least one data point")
		} else {
			dp := hist.DataPoints[0]
			if dp.Count != 1 {
				t.Errorf("expected count=1, got %d", dp.Count)
			}
			if dp.Sum != 1.5 {
				t.Errorf("expected sum=1.5, got %f", dp.Sum)
			}
		}
	}

	// Verify package count was recorded
	pkgMetric := findMetric(&rm, "deputy.scan.packages")
	if pkgMetric == nil {
		t.Error("expected deputy.scan.packages metric to be recorded")
	} else {
		sum, ok := pkgMetric.Data.(metricdata.Sum[int64])
		if !ok {
			t.Errorf("expected Sum data, got %T", pkgMetric.Data)
		} else if len(sum.DataPoints) == 0 {
			t.Error("expected at least one data point")
		} else {
			total := int64(0)
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			if total != 100 {
				t.Errorf("expected total packages=100, got %d", total)
			}
		}
	}

	// Verify vulnerability counts by severity
	vulnMetric := findMetric(&rm, "deputy.scan.vulnerabilities")
	if vulnMetric == nil {
		t.Error("expected deputy.scan.vulnerabilities metric to be recorded")
	} else {
		sum, ok := vulnMetric.Data.(metricdata.Sum[int64])
		if !ok {
			t.Errorf("expected Sum data, got %T", vulnMetric.Data)
		} else {
			// Should have data points for CRITICAL and HIGH
			if len(sum.DataPoints) < 2 {
				t.Errorf("expected at least 2 data points (CRITICAL, HIGH), got %d", len(sum.DataPoints))
			}
		}
	}
}

func TestRecordProxyRequest_RecordsValues(t *testing.T) {
	reader := setupTestMeterProvider(t)
	ctx := context.Background()

	RecordProxyRequest(ctx, 0.25, "npm", 200)
	RecordProxyRequest(ctx, 0.15, "npm", 200)
	RecordProxyRequest(ctx, 0.50, "go", 403)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("failed to collect metrics: %v", err)
	}

	// Verify request counter
	reqMetric := findMetric(&rm, "deputy.proxy.requests")
	if reqMetric == nil {
		t.Error("expected deputy.proxy.requests metric to be recorded")
	} else {
		sum, ok := reqMetric.Data.(metricdata.Sum[int64])
		if !ok {
			t.Errorf("expected Sum data, got %T", reqMetric.Data)
		} else {
			total := int64(0)
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			if total != 3 {
				t.Errorf("expected 3 total requests, got %d", total)
			}
		}
	}

	// Verify duration histogram
	durMetric := findMetric(&rm, "deputy.proxy.request.duration")
	if durMetric == nil {
		t.Error("expected deputy.proxy.request.duration metric to be recorded")
	} else {
		hist, ok := durMetric.Data.(metricdata.Histogram[float64])
		if !ok {
			t.Errorf("expected Histogram data, got %T", durMetric.Data)
		} else {
			totalCount := uint64(0)
			for _, dp := range hist.DataPoints {
				totalCount += dp.Count
			}
			if totalCount != 3 {
				t.Errorf("expected 3 histogram entries, got %d", totalCount)
			}
		}
	}
}

func TestRecordPolicyEvaluation_RecordsValues(t *testing.T) {
	reader := setupTestMeterProvider(t)
	ctx := context.Background()

	RecordPolicyEvaluation(ctx, 0.05, "allow")
	RecordPolicyEvaluation(ctx, 0.10, "allow")
	RecordPolicyEvaluation(ctx, 0.02, "deny")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("failed to collect metrics: %v", err)
	}

	// Verify evaluation counter
	evalMetric := findMetric(&rm, "deputy.policy.evaluations")
	if evalMetric == nil {
		t.Error("expected deputy.policy.evaluations metric to be recorded")
	} else {
		sum, ok := evalMetric.Data.(metricdata.Sum[int64])
		if !ok {
			t.Errorf("expected Sum data, got %T", evalMetric.Data)
		} else {
			total := int64(0)
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			if total != 3 {
				t.Errorf("expected 3 total evaluations, got %d", total)
			}
		}
	}

	// Verify duration histogram
	durMetric := findMetric(&rm, "deputy.policy.duration")
	if durMetric == nil {
		t.Error("expected deputy.policy.duration metric to be recorded")
	} else {
		hist, ok := durMetric.Data.(metricdata.Histogram[float64])
		if !ok {
			t.Errorf("expected Histogram data, got %T", durMetric.Data)
		} else {
			totalCount := uint64(0)
			totalSum := float64(0)
			for _, dp := range hist.DataPoints {
				totalCount += dp.Count
				totalSum += dp.Sum
			}
			if totalCount != 3 {
				t.Errorf("expected 3 histogram entries, got %d", totalCount)
			}
			expectedSum := 0.05 + 0.10 + 0.02
			if totalSum < expectedSum-0.001 || totalSum > expectedSum+0.001 {
				t.Errorf("expected sum ~%f, got %f", expectedSum, totalSum)
			}
		}
	}
}

func TestRecordOSVCacheAccess_RecordsValues(t *testing.T) {
	reader := setupTestMeterProvider(t)
	ctx := context.Background()

	RecordOSVCacheAccess(ctx, true)
	RecordOSVCacheAccess(ctx, true)
	RecordOSVCacheAccess(ctx, true)
	RecordOSVCacheAccess(ctx, false)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("failed to collect metrics: %v", err)
	}

	// Verify cache hits
	hitsMetric := findMetric(&rm, "deputy.osv.cache.hits")
	if hitsMetric == nil {
		t.Error("expected deputy.osv.cache.hits metric to be recorded")
	} else {
		sum, ok := hitsMetric.Data.(metricdata.Sum[int64])
		if !ok {
			t.Errorf("expected Sum data, got %T", hitsMetric.Data)
		} else {
			total := int64(0)
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			if total != 3 {
				t.Errorf("expected 3 cache hits, got %d", total)
			}
		}
	}

	// Verify cache misses
	missesMetric := findMetric(&rm, "deputy.osv.cache.misses")
	if missesMetric == nil {
		t.Error("expected deputy.osv.cache.misses metric to be recorded")
	} else {
		sum, ok := missesMetric.Data.(metricdata.Sum[int64])
		if !ok {
			t.Errorf("expected Sum data, got %T", missesMetric.Data)
		} else {
			total := int64(0)
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			if total != 1 {
				t.Errorf("expected 1 cache miss, got %d", total)
			}
		}
	}
}

func TestRecordProxyAuth_RecordsValues(t *testing.T) {
	reader := setupTestMeterProvider(t)
	ctx := context.Background()

	RecordProxyAuth(ctx, "success", "")
	RecordProxyAuth(ctx, "success", "")
	RecordProxyAuth(ctx, "rejected", "invalid_token")
	RecordProxyAuth(ctx, "anonymous", "")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("failed to collect metrics: %v", err)
	}

	authMetric := findMetric(&rm, "deputy.proxy.auth")
	if authMetric == nil {
		t.Error("expected deputy.proxy.auth metric to be recorded")
	} else {
		sum, ok := authMetric.Data.(metricdata.Sum[int64])
		if !ok {
			t.Errorf("expected Sum data, got %T", authMetric.Data)
		} else {
			total := int64(0)
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			if total != 4 {
				t.Errorf("expected 4 total auth attempts, got %d", total)
			}
		}
	}
}

func TestRecordOSVQuery_DoesNotPanic(t *testing.T) {
	ctx := context.Background()

	// Should not panic
	RecordOSVQuery(ctx, 0.5, "batch", true)
	RecordOSVQuery(ctx, 0.3, "single", false)
}

func TestRecordOSVCacheAccess_DoesNotPanic(t *testing.T) {
	ctx := context.Background()

	// Should not panic
	RecordOSVCacheAccess(ctx, true)
	RecordOSVCacheAccess(ctx, false)
}

func TestRecordPolicyEvaluation_DoesNotPanic(t *testing.T) {
	ctx := context.Background()

	// Should not panic
	RecordPolicyEvaluation(ctx, 0.1, "allow")
	RecordPolicyEvaluation(ctx, 0.2, "deny")
	RecordPolicyEvaluation(ctx, 0.05, "warn")
}

func TestRecordProxyRequest_DoesNotPanic(t *testing.T) {
	ctx := context.Background()

	// Should not panic
	RecordProxyRequest(ctx, 0.5, "go", 200)
	RecordProxyRequest(ctx, 0.3, "npm", 403)
}

func TestRecordProxyAuth_DoesNotPanic(t *testing.T) {
	ctx := context.Background()

	// Should not panic
	RecordProxyAuth(ctx, "success", "")
	RecordProxyAuth(ctx, "rejected", "invalid_token")
	RecordProxyAuth(ctx, "anonymous", "")
}

func TestRecordProxyPolicyDenial_DoesNotPanic(t *testing.T) {
	ctx := context.Background()

	// Should not panic
	RecordProxyPolicyDenial(ctx, "go", "block-critical")
}

func TestSeverityCounts_ToMap(t *testing.T) {
	sc := SeverityCounts{
		Critical: 1,
		High:     2,
		Medium:   3,
		Low:      4,
	}

	m := sc.ToMap()

	if m["CRITICAL"] != 1 {
		t.Errorf("expected CRITICAL=1, got %d", m["CRITICAL"])
	}
	if m["HIGH"] != 2 {
		t.Errorf("expected HIGH=2, got %d", m["HIGH"])
	}
	if m["MEDIUM"] != 3 {
		t.Errorf("expected MEDIUM=3, got %d", m["MEDIUM"])
	}
	if m["LOW"] != 4 {
		t.Errorf("expected LOW=4, got %d", m["LOW"])
	}
}

func TestSeverityCounts_Total(t *testing.T) {
	tests := []struct {
		name     string
		sc       SeverityCounts
		expected int
	}{
		{"all zeros", SeverityCounts{}, 0},
		{"all ones", SeverityCounts{Critical: 1, High: 1, Medium: 1, Low: 1}, 4},
		{"mixed", SeverityCounts{Critical: 5, High: 10, Medium: 15, Low: 20}, 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sc.Total(); got != tt.expected {
				t.Errorf("Total() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestCacheTypeAttr(t *testing.T) {
	attr := CacheTypeAttr("depsdev")
	if string(attr.Key) != "deputy.cache.type" {
		t.Errorf("expected key 'deputy.cache.type', got %q", attr.Key)
	}
	if attr.Value.AsString() != "depsdev" {
		t.Errorf("expected value 'depsdev', got %q", attr.Value.AsString())
	}
}

func TestRecordCacheStats_DoesNotPanic(t *testing.T) {
	ctx := context.Background()

	stats := CacheStats{
		Hits:    100,
		Misses:  25,
		Evicted: 10,
		Expired: 5,
		Size:    50,
		MaxSize: 100,
		HitRate: 0.8,
	}

	// Should not panic
	RecordCacheStats(ctx, "depsdev", stats)
	RecordCacheStats(ctx, "goproxy", stats)
}

func TestRecordCacheStats_RecordsValues(t *testing.T) {
	reader := setupTestMeterProvider(t)
	ctx := context.Background()

	stats := CacheStats{
		Hits:    100,
		Misses:  25,
		Evicted: 10,
		Expired: 5,
		Size:    50,
		MaxSize: 100,
		HitRate: 0.8,
	}

	RecordCacheStats(ctx, "depsdev", stats)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("failed to collect metrics: %v", err)
	}

	// Verify cache size gauge was recorded
	sizeMetric := findMetric(&rm, "deputy.cache.size")
	if sizeMetric == nil {
		t.Error("expected deputy.cache.size metric to be recorded")
	}

	// Verify cache max_size gauge was recorded
	maxSizeMetric := findMetric(&rm, "deputy.cache.max_size")
	if maxSizeMetric == nil {
		t.Error("expected deputy.cache.max_size metric to be recorded")
	}

	// Verify cache hit_rate gauge was recorded
	hitRateMetric := findMetric(&rm, "deputy.cache.hit_rate")
	if hitRateMetric == nil {
		t.Error("expected deputy.cache.hit_rate metric to be recorded")
	}
}

func TestRecordCacheHitMiss_RecordsValues(t *testing.T) {
	reader := setupTestMeterProvider(t)
	ctx := context.Background()

	RecordCacheHit(ctx, "depsdev")
	RecordCacheHit(ctx, "depsdev")
	RecordCacheHit(ctx, "goproxy")
	RecordCacheMiss(ctx, "depsdev")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("failed to collect metrics: %v", err)
	}

	// Verify cache hits
	hitsMetric := findMetric(&rm, "deputy.cache.hits")
	if hitsMetric == nil {
		t.Error("expected deputy.cache.hits metric to be recorded")
	} else {
		sum, ok := hitsMetric.Data.(metricdata.Sum[int64])
		if !ok {
			t.Errorf("expected Sum data, got %T", hitsMetric.Data)
		} else {
			total := int64(0)
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			if total != 3 {
				t.Errorf("expected 3 cache hits, got %d", total)
			}
		}
	}

	// Verify cache misses
	missesMetric := findMetric(&rm, "deputy.cache.misses")
	if missesMetric == nil {
		t.Error("expected deputy.cache.misses metric to be recorded")
	} else {
		sum, ok := missesMetric.Data.(metricdata.Sum[int64])
		if !ok {
			t.Errorf("expected Sum data, got %T", missesMetric.Data)
		} else {
			total := int64(0)
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			if total != 1 {
				t.Errorf("expected 1 cache miss, got %d", total)
			}
		}
	}
}

func TestRecordCacheEvictionExpiration_RecordsValues(t *testing.T) {
	reader := setupTestMeterProvider(t)
	ctx := context.Background()

	RecordCacheEviction(ctx, "depsdev")
	RecordCacheEviction(ctx, "depsdev")
	RecordCacheExpiration(ctx, "goproxy")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("failed to collect metrics: %v", err)
	}

	// Verify cache evictions
	evictMetric := findMetric(&rm, "deputy.cache.evictions")
	if evictMetric == nil {
		t.Error("expected deputy.cache.evictions metric to be recorded")
	} else {
		sum, ok := evictMetric.Data.(metricdata.Sum[int64])
		if !ok {
			t.Errorf("expected Sum data, got %T", evictMetric.Data)
		} else {
			total := int64(0)
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			if total != 2 {
				t.Errorf("expected 2 cache evictions, got %d", total)
			}
		}
	}

	// Verify cache expirations
	expiredMetric := findMetric(&rm, "deputy.cache.expired")
	if expiredMetric == nil {
		t.Error("expected deputy.cache.expired metric to be recorded")
	} else {
		sum, ok := expiredMetric.Data.(metricdata.Sum[int64])
		if !ok {
			t.Errorf("expected Sum data, got %T", expiredMetric.Data)
		} else {
			total := int64(0)
			for _, dp := range sum.DataPoints {
				total += dp.Value
			}
			if total != 1 {
				t.Errorf("expected 1 cache expiration, got %d", total)
			}
		}
	}
}

func TestRecordCacheHit_DoesNotPanic(t *testing.T) {
	ctx := context.Background()
	// Should not panic
	RecordCacheHit(ctx, "test")
}

func TestRecordCacheMiss_DoesNotPanic(t *testing.T) {
	ctx := context.Background()
	// Should not panic
	RecordCacheMiss(ctx, "test")
}

func TestRecordCacheEviction_DoesNotPanic(t *testing.T) {
	ctx := context.Background()
	// Should not panic
	RecordCacheEviction(ctx, "test")
}

func TestRecordCacheExpiration_DoesNotPanic(t *testing.T) {
	ctx := context.Background()
	// Should not panic
	RecordCacheExpiration(ctx, "test")
}

func TestPredefinedAttributes(t *testing.T) {
	// Test ecosystem attributes have correct keys
	t.Run("ecosystem attributes", func(t *testing.T) {
		attrs := []struct {
			name string
			attr interface{ Valid() bool }
		}{
			{"AttrEcosystemGo", AttrEcosystemGo},
			{"AttrEcosystemNpm", AttrEcosystemNpm},
			{"AttrEcosystemPyPI", AttrEcosystemPyPI},
		}
		for _, tt := range attrs {
			if !tt.attr.Valid() {
				t.Errorf("%s is not valid", tt.name)
			}
		}
	})

	// Test severity attributes have correct keys
	t.Run("severity attributes", func(t *testing.T) {
		attrs := []struct {
			name string
			attr interface{ Valid() bool }
		}{
			{"AttrSeverityCritical", AttrSeverityCritical},
			{"AttrSeverityHigh", AttrSeverityHigh},
			{"AttrSeverityMedium", AttrSeverityMedium},
			{"AttrSeverityLow", AttrSeverityLow},
		}
		for _, tt := range attrs {
			if !tt.attr.Valid() {
				t.Errorf("%s is not valid", tt.name)
			}
		}
	})
}
