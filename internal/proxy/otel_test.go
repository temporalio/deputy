package proxy

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	otelTrace "go.opentelemetry.io/otel/trace"
)

// testTracer creates a tracer with an in-memory span recorder for testing.
// Returns the tracer and the span recorder for assertions.
func testTracer(t *testing.T) (otelTrace.Tracer, *tracetest.SpanRecorder) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
	})
	return tp.Tracer("test"), recorder
}

// startTestSpan creates a span for testing that will be recorded.
func startTestSpan(ctx context.Context, tracer otelTrace.Tracer, name string) (context.Context, otelTrace.Span) {
	return tracer.Start(ctx, name)
}

// assertAttribute checks that a span has an attribute with the expected value.
func assertAttribute(t *testing.T, span sdktrace.ReadOnlySpan, key string, expected any) {
	t.Helper()
	for _, attr := range span.Attributes() {
		if string(attr.Key) == key {
			switch v := expected.(type) {
			case string:
				if attr.Value.AsString() != v {
					t.Errorf("attribute %q = %q, want %q", key, attr.Value.AsString(), v)
				}
				return
			case bool:
				if attr.Value.AsBool() != v {
					t.Errorf("attribute %q = %v, want %v", key, attr.Value.AsBool(), v)
				}
				return
			case int:
				if attr.Value.AsInt64() != int64(v) {
					t.Errorf("attribute %q = %d, want %d", key, attr.Value.AsInt64(), v)
				}
				return
			case int64:
				if attr.Value.AsInt64() != v {
					t.Errorf("attribute %q = %d, want %d", key, attr.Value.AsInt64(), v)
				}
				return
			default:
				t.Errorf("unsupported expected type %T", expected)
			}
			return
		}
	}
	t.Errorf("attribute %q not found in span", key)
}

// assertHasAttribute checks that a span has an attribute (any value).
func assertHasAttribute(t *testing.T, span sdktrace.ReadOnlySpan, key string) {
	t.Helper()
	for _, attr := range span.Attributes() {
		if string(attr.Key) == key {
			return
		}
	}
	t.Errorf("attribute %q not found in span", key)
}

// assertEventExists checks that a span has an event with the given name.
func assertEventExists(t *testing.T, span sdktrace.ReadOnlySpan, eventName string) {
	t.Helper()
	for _, event := range span.Events() {
		if event.Name == eventName {
			return
		}
	}
	t.Errorf("event %q not found in span", eventName)
}

// getEvent returns the first event with the given name, or nil if not found.
func getEvent(span sdktrace.ReadOnlySpan, eventName string) *sdktrace.Event {
	for _, event := range span.Events() {
		if event.Name == eventName {
			e := event // copy to avoid returning pointer to loop variable
			return &e
		}
	}
	return nil
}

// assertEventAttribute checks that an event has an attribute with the expected value.
func assertEventAttribute(t *testing.T, event *sdktrace.Event, key string, expected any) {
	t.Helper()
	if event == nil {
		t.Error("event is nil")
		return
	}
	for _, attr := range event.Attributes {
		if string(attr.Key) == key {
			switch v := expected.(type) {
			case string:
				if attr.Value.AsString() != v {
					t.Errorf("event attribute %q = %q, want %q", key, attr.Value.AsString(), v)
				}
				return
			case bool:
				if attr.Value.AsBool() != v {
					t.Errorf("event attribute %q = %v, want %v", key, attr.Value.AsBool(), v)
				}
				return
			case int:
				if attr.Value.AsInt64() != int64(v) {
					t.Errorf("event attribute %q = %d, want %d", key, attr.Value.AsInt64(), v)
				}
				return
			default:
				t.Errorf("unsupported expected type %T", expected)
			}
			return
		}
	}
	t.Errorf("event attribute %q not found", key)
}

func TestEnrichSpanWithRequest(t *testing.T) {
	tests := []struct {
		name     string
		info     RequestInfo
		wantKeys []string
	}{
		{
			name: "full request info",
			info: RequestInfo{
				Ecosystem:  "go",
				Package:    "github.com/example/pkg",
				Version:    "v1.2.3",
				Operation:  "download",
				Listener:   "go-proxy",
				Upstream:   "https://proxy.golang.org",
				HasVersion: true,
			},
			wantKeys: []string{
				"deputy.proxy.ecosystem",
				"deputy.proxy.package",
				"deputy.proxy.version",
				"deputy.proxy.operation",
				"deputy.proxy.listener",
				"deputy.proxy.upstream",
			},
		},
		{
			name: "minimal request info",
			info: RequestInfo{
				Ecosystem: "npm",
				Package:   "lodash",
				Operation: "info",
			},
			wantKeys: []string{
				"deputy.proxy.ecosystem",
				"deputy.proxy.package",
				"deputy.proxy.operation",
			},
		},
		{
			name: "version not included when HasVersion is false",
			info: RequestInfo{
				Ecosystem:  "go",
				Package:    "github.com/example/pkg",
				Version:    "v1.2.3", // present but HasVersion=false
				Operation:  "list",
				HasVersion: false,
			},
			wantKeys: []string{
				"deputy.proxy.ecosystem",
				"deputy.proxy.package",
				"deputy.proxy.operation",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracer, recorder := testTracer(t)
			ctx, span := startTestSpan(context.Background(), tracer, "test")
			EnrichSpanWithRequest(span, tt.info)
			span.End()

			spans := recorder.Ended()
			if len(spans) != 1 {
				t.Fatalf("expected 1 span, got %d", len(spans))
			}

			for _, key := range tt.wantKeys {
				assertHasAttribute(t, spans[0], key)
			}

			// Verify specific values
			assertAttribute(t, spans[0], "deputy.proxy.ecosystem", tt.info.Ecosystem)
			assertAttribute(t, spans[0], "deputy.proxy.package", tt.info.Package)
			assertAttribute(t, spans[0], "deputy.proxy.operation", tt.info.Operation)

			_ = ctx // suppress unused warning
		})
	}
}

func TestRecordAuthEvent(t *testing.T) {
	tests := []struct {
		name       string
		data       AuthEventData
		wantResult string
	}{
		{
			name: "successful auth",
			data: AuthEventData{
				Result:    AuthResultSuccess,
				Subject:   "user:alice",
				Anonymous: false,
			},
			wantResult: "success",
		},
		{
			name: "anonymous request",
			data: AuthEventData{
				Result:    AuthResultAnonymous,
				Anonymous: true,
			},
			wantResult: "anonymous",
		},
		{
			name: "rejected auth",
			data: AuthEventData{
				Result:    AuthResultRejected,
				ErrorCode: "invalid_token",
				Anonymous: false,
			},
			wantResult: "rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracer, recorder := testTracer(t)
			ctx, span := startTestSpan(context.Background(), tracer, "test")
			RecordAuthEvent(ctx, span, tt.data)
			span.End()

			spans := recorder.Ended()
			if len(spans) != 1 {
				t.Fatalf("expected 1 span, got %d", len(spans))
			}

			assertEventExists(t, spans[0], "auth.completed")
			event := getEvent(spans[0], "auth.completed")
			assertEventAttribute(t, event, "deputy.proxy.auth.result", tt.wantResult)
			assertEventAttribute(t, event, "deputy.proxy.auth.anonymous", tt.data.Anonymous)

			if tt.data.Subject != "" {
				assertEventAttribute(t, event, "deputy.proxy.auth.subject", tt.data.Subject)
			}
			if tt.data.ErrorCode != "" {
				assertEventAttribute(t, event, "deputy.proxy.auth.error_code", tt.data.ErrorCode)
			}
		})
	}
}

func TestRecordAuthHelpers(t *testing.T) {
	t.Run("RecordAuthSuccess", func(t *testing.T) {
		tracer, recorder := testTracer(t)
		ctx, span := startTestSpan(context.Background(), tracer, "test")
		RecordAuthSuccess(ctx, span, "user:bob")
		span.End()

		spans := recorder.Ended()
		event := getEvent(spans[0], "auth.completed")
		assertEventAttribute(t, event, "deputy.proxy.auth.result", "success")
		assertEventAttribute(t, event, "deputy.proxy.auth.subject", "user:bob")
		assertEventAttribute(t, event, "deputy.proxy.auth.anonymous", false)
	})

	t.Run("RecordAuthAnonymous", func(t *testing.T) {
		tracer, recorder := testTracer(t)
		ctx, span := startTestSpan(context.Background(), tracer, "test")
		RecordAuthAnonymous(ctx, span)
		span.End()

		spans := recorder.Ended()
		event := getEvent(spans[0], "auth.completed")
		assertEventAttribute(t, event, "deputy.proxy.auth.result", "anonymous")
		assertEventAttribute(t, event, "deputy.proxy.auth.anonymous", true)
	})

	t.Run("RecordAuthRejected", func(t *testing.T) {
		tracer, recorder := testTracer(t)
		ctx, span := startTestSpan(context.Background(), tracer, "test")
		RecordAuthRejected(ctx, span, "expired_token")
		span.End()

		spans := recorder.Ended()
		event := getEvent(spans[0], "auth.completed")
		assertEventAttribute(t, event, "deputy.proxy.auth.result", "rejected")
		assertEventAttribute(t, event, "deputy.proxy.auth.error_code", "expired_token")
	})
}

func TestRecordPolicyEvent(t *testing.T) {
	tests := []struct {
		name string
		data PolicyEventData
	}{
		{
			name: "policy allow",
			data: PolicyEventData{
				Result:     PolicyResultAllow,
				Entrypoint: "go_artifact_request",
			},
		},
		{
			name: "policy deny",
			data: PolicyEventData{
				Result:     PolicyResultDeny,
				Entrypoint: "npm_artifact_request",
				PolicyName: "block-critical",
				Reason:     "Critical vulnerability found",
			},
		},
		{
			name: "policy allow with warnings",
			data: PolicyEventData{
				Result:       PolicyResultWarn,
				Entrypoint:   "go_artifact_request",
				WarningCount: 3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracer, recorder := testTracer(t)
			ctx, span := startTestSpan(context.Background(), tracer, "test")
			RecordPolicyEvent(ctx, span, tt.data)
			span.End()

			spans := recorder.Ended()
			assertEventExists(t, spans[0], "policy.evaluated")
			event := getEvent(spans[0], "policy.evaluated")
			assertEventAttribute(t, event, "deputy.proxy.policy.result", string(tt.data.Result))
			assertEventAttribute(t, event, "deputy.policy.entrypoint", tt.data.Entrypoint) // Reused from central otel

			if tt.data.PolicyName != "" {
				assertEventAttribute(t, event, "deputy.policy.name", tt.data.PolicyName) // Reused from central otel
			}
			if tt.data.Reason != "" {
				assertEventAttribute(t, event, "deputy.proxy.policy.reason", tt.data.Reason)
			}
			if tt.data.WarningCount > 0 {
				assertEventAttribute(t, event, "deputy.proxy.policy.warnings", tt.data.WarningCount)
			}
		})
	}
}

func TestRecordPolicyHelpers(t *testing.T) {
	t.Run("RecordPolicyAllow", func(t *testing.T) {
		tracer, recorder := testTracer(t)
		ctx, span := startTestSpan(context.Background(), tracer, "test")
		RecordPolicyAllow(ctx, span, "go_artifact_request", 2, 50*time.Millisecond)
		span.End()

		spans := recorder.Ended()
		event := getEvent(spans[0], "policy.evaluated")
		assertEventAttribute(t, event, "deputy.proxy.policy.result", "allow")
		assertEventAttribute(t, event, "deputy.policy.entrypoint", "go_artifact_request") // Reused from central otel
		assertEventAttribute(t, event, "deputy.proxy.policy.warnings", 2)
	})

	t.Run("RecordPolicyDeny", func(t *testing.T) {
		tracer, recorder := testTracer(t)
		ctx, span := startTestSpan(context.Background(), tracer, "test")
		RecordPolicyDeny(ctx, span, "npm_artifact_request", "block-critical", "has critical vuln", "npm", 30*time.Millisecond)
		span.End()

		spans := recorder.Ended()
		event := getEvent(spans[0], "policy.evaluated")
		assertEventAttribute(t, event, "deputy.proxy.policy.result", "deny")
		assertEventAttribute(t, event, "deputy.policy.name", "block-critical") // Reused from central otel
		assertEventAttribute(t, event, "deputy.proxy.policy.reason", "has critical vuln")
	})
}

func TestRecordCacheEvent(t *testing.T) {
	tests := []struct {
		name string
		data CacheEventData
	}{
		{
			name: "osv cache hit",
			data: CacheEventData{
				Type: CacheTypeOSV,
				Hit:  true,
				Key:  "go|github.com/example/pkg@v1.0.0",
			},
		},
		{
			name: "osv cache miss",
			data: CacheEventData{
				Type: CacheTypeOSV,
				Hit:  false,
				Key:  "npm|lodash@4.17.21",
			},
		},
		{
			name: "license cache hit",
			data: CacheEventData{
				Type: CacheTypeLicense,
				Hit:  true,
				Key:  "go|github.com/example/pkg@v1.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tracer, recorder := testTracer(t)
			ctx, span := startTestSpan(context.Background(), tracer, "test")
			RecordCacheEvent(ctx, span, tt.data)
			span.End()

			spans := recorder.Ended()
			assertEventExists(t, spans[0], "cache.access")
			event := getEvent(spans[0], "cache.access")
			assertEventAttribute(t, event, "deputy.cache.type", string(tt.data.Type))
			assertEventAttribute(t, event, "deputy.cache.hit", tt.data.Hit)
			if tt.data.Key != "" {
				assertEventAttribute(t, event, "deputy.cache.key", tt.data.Key)
			}
		})
	}
}

func TestRecordCacheHelpers(t *testing.T) {
	t.Run("RecordOSVCacheHit", func(t *testing.T) {
		tracer, recorder := testTracer(t)
		ctx, span := startTestSpan(context.Background(), tracer, "test")
		RecordOSVCacheHit(ctx, span, "go|pkg@v1")
		span.End()

		spans := recorder.Ended()
		event := getEvent(spans[0], "cache.access")
		assertEventAttribute(t, event, "deputy.cache.type", "osv")
		assertEventAttribute(t, event, "deputy.cache.hit", true)
	})

	t.Run("RecordOSVCacheMiss", func(t *testing.T) {
		tracer, recorder := testTracer(t)
		ctx, span := startTestSpan(context.Background(), tracer, "test")
		RecordOSVCacheMiss(ctx, span, "go|pkg@v1")
		span.End()

		spans := recorder.Ended()
		event := getEvent(spans[0], "cache.access")
		assertEventAttribute(t, event, "deputy.cache.type", "osv")
		assertEventAttribute(t, event, "deputy.cache.hit", false)
	})

	t.Run("RecordLicenseCacheHit", func(t *testing.T) {
		tracer, recorder := testTracer(t)
		ctx, span := startTestSpan(context.Background(), tracer, "test")
		RecordLicenseCacheHit(ctx, span, "npm|pkg@1.0")
		span.End()

		spans := recorder.Ended()
		event := getEvent(spans[0], "cache.access")
		assertEventAttribute(t, event, "deputy.cache.type", "license")
		assertEventAttribute(t, event, "deputy.cache.hit", true)
	})
}

func TestRecordVulnerabilityCount(t *testing.T) {
	tracer, recorder := testTracer(t)
	_, span := startTestSpan(context.Background(), tracer, "test")
	RecordVulnerabilityCount(span, 5)
	span.End()

	spans := recorder.Ended()
	assertAttribute(t, spans[0], "deputy.proxy.vuln.count", 5)
}

func TestProxyRequestRecorder(t *testing.T) {
	// Just verify it doesn't panic; actual metric recording is tested elsewhere
	ctx := context.Background()
	recorder := NewProxyRequestRecorder(ctx, "go")

	// Simulate some work
	recorder.Complete(200)
}

func TestMultipleEventsOnSameSpan(t *testing.T) {
	// Test that multiple events can be recorded on the same span
	tracer, recorder := testTracer(t)
	ctx, span := startTestSpan(context.Background(), tracer, "test")

	// Record auth
	RecordAuthSuccess(ctx, span, "user:alice")

	// Record cache access
	RecordOSVCacheHit(ctx, span, "go|pkg@v1")
	RecordLicenseCacheMiss(ctx, span, "go|pkg@v1")

	// Record policy
	RecordPolicyAllow(ctx, span, "go_artifact_request", 0, 10*time.Millisecond)

	span.End()

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}

	// Should have 4 events
	if len(spans[0].Events()) != 4 {
		t.Errorf("expected 4 events, got %d", len(spans[0].Events()))
	}

	assertEventExists(t, spans[0], "auth.completed")
	assertEventExists(t, spans[0], "policy.evaluated")

	// Count cache.access events (should be 2)
	cacheEvents := 0
	for _, event := range spans[0].Events() {
		if event.Name == "cache.access" {
			cacheEvents++
		}
	}
	if cacheEvents != 2 {
		t.Errorf("expected 2 cache.access events, got %d", cacheEvents)
	}
}

func TestEnrichSpanWithRequest_EmptyStrings(t *testing.T) {
	// Test that empty strings don't cause issues
	tracer, recorder := testTracer(t)
	_, span := startTestSpan(context.Background(), tracer, "test")

	EnrichSpanWithRequest(span, RequestInfo{
		Ecosystem: "",
		Package:   "",
		Operation: "",
	})
	span.End()

	spans := recorder.Ended()
	// Should still have the attributes, just with empty values
	assertHasAttribute(t, spans[0], "deputy.proxy.ecosystem")
	assertHasAttribute(t, spans[0], "deputy.proxy.package")
	assertHasAttribute(t, spans[0], "deputy.proxy.operation")
}

func TestAttributeKeyConsistency(t *testing.T) {
	// Verify that proxy-specific attribute keys follow the expected naming convention.
	// Keys reused from the central otel package (like attrProxyPackage) may have
	// different prefixes, so we only check the locally-defined keys.
	expectedPrefix := "deputy.proxy."

	// Only check proxy-specific keys defined locally (not reused from central otel)
	proxySpecificKeys := []attribute.Key{
		attrProxyEcosystem, // Local: deputy.proxy.ecosystem
		attrAuthResult,     // Local: deputy.proxy.auth.result
		attrAuthSubject,    // Local: deputy.proxy.auth.subject
		attrAuthErrorCode,  // Local: deputy.proxy.auth.error_code
		attrAuthAnonymous,  // Local: deputy.proxy.auth.anonymous
		attrPolicyResult,   // Local: deputy.proxy.policy.result
		attrPolicyReason,   // Local: deputy.proxy.policy.reason
		attrPolicyWarnings, // Local: deputy.proxy.policy.warnings
		attrVulnCount,      // Local: deputy.proxy.vuln.count
	}

	for _, key := range proxySpecificKeys {
		if len(string(key)) < len(expectedPrefix) {
			t.Errorf("key %q is too short", key)
			continue
		}
		if string(key)[:len(expectedPrefix)] != expectedPrefix {
			t.Errorf("key %q does not start with %q", key, expectedPrefix)
		}
	}

	// Verify reused keys from central otel package have expected values
	reuseTests := []struct {
		key      attribute.Key
		expected string
	}{
		{attrProxyPackage, "deputy.proxy.package"},
		{attrProxyVersion, "deputy.proxy.version"},
		{attrProxyOperation, "deputy.proxy.operation"},
		{attrProxyUpstream, "deputy.proxy.upstream"},
		{attrProxyListenerID, "deputy.proxy.listener"},
		{attrPolicyName, "deputy.policy.name"},
		{attrPolicyEntrypoint, "deputy.policy.entrypoint"},
		{attrCacheType, "deputy.cache.type"},
		{attrCacheHit, "deputy.cache.hit"},
		{attrCacheKey, "deputy.cache.key"},
	}

	for _, tt := range reuseTests {
		if string(tt.key) != tt.expected {
			t.Errorf("reused key has value %q, want %q", tt.key, tt.expected)
		}
	}
}

func TestAuthResultConstants(t *testing.T) {
	// Verify constants have expected string values
	tests := []struct {
		result AuthResult
		want   string
	}{
		{AuthResultSuccess, "success"},
		{AuthResultAnonymous, "anonymous"},
		{AuthResultRejected, "rejected"},
		{AuthResultError, "error"},
	}

	for _, tt := range tests {
		if string(tt.result) != tt.want {
			t.Errorf("AuthResult constant %q has value %q, want %q", tt.result, string(tt.result), tt.want)
		}
	}
}

func TestPolicyResultConstants(t *testing.T) {
	// Verify constants have expected string values
	tests := []struct {
		result PolicyResult
		want   string
	}{
		{PolicyResultAllow, "allow"},
		{PolicyResultDeny, "deny"},
		{PolicyResultWarn, "warn"},
		{PolicyResultError, "error"},
	}

	for _, tt := range tests {
		if string(tt.result) != tt.want {
			t.Errorf("PolicyResult constant %q has value %q, want %q", tt.result, string(tt.result), tt.want)
		}
	}
}

func TestCacheTypeConstants(t *testing.T) {
	// Verify constants have expected string values
	tests := []struct {
		ctype CacheType
		want  string
	}{
		{CacheTypeOSV, "osv"},
		{CacheTypeLicense, "license"},
	}

	for _, tt := range tests {
		if string(tt.ctype) != tt.want {
			t.Errorf("CacheType constant %q has value %q, want %q", tt.ctype, string(tt.ctype), tt.want)
		}
	}
}
