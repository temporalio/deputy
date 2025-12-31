package proxy

import (
	"log/slog"
	"net/http"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// serveWithPolicy evaluates policies for a request and, if allowed, forwards it to upstream.
//
// It applies any action headers, logs warnings/denies, and ensures deny responses include
// stable `X-Deputy-*` headers for downstream tooling.
//
// Span enrichment: This function adds policy evaluation events to the current span,
// recording the evaluation result (allow/deny/warn), entrypoint, and any denial reason.
func serveWithPolicy(w http.ResponseWriter, r *http.Request, policies PolicyEvaluator, entrypoint string, payload map[string]any, meta blockMeta, upstream http.Handler) {
	if w == nil || r == nil || upstream == nil {
		return
	}

	ctx := r.Context()
	span := trace.SpanFromContext(ctx)

	// Enrich span with request info
	EnrichSpanWithRequest(span, RequestInfo{
		Ecosystem:  meta.Ecosystem,
		Package:    meta.Name,
		Version:    meta.Version,
		Operation:  meta.Operation,
		HasVersion: meta.Version != "",
	})

	if policies != nil {
		evalStart := time.Now()
		actions, err := policies.Evaluate(ctx, entrypoint, payload)
		evalDuration := time.Since(evalStart)

		if err != nil {
			RecordPolicyEvent(ctx, span, PolicyEventData{
				Result:     PolicyResultError,
				Duration:   evalDuration,
				Entrypoint: entrypoint,
				Reason:     err.Error(),
			})
			http.Error(w, "policy evaluation failed", http.StatusInternalServerError)
			slog.Error("policy evaluation failed",
				"entrypoint", entrypoint,
				"ecosystem", meta.Ecosystem,
				"name", meta.Name,
				"version", meta.Version,
				"operation", meta.Operation,
				"error", err,
			)
			return
		}

		deny, warns, hdrs := summarizeActions(actions)
		for k, v := range hdrs {
			w.Header().Set(k, v)
		}
		for _, warn := range warns {
			slog.Warn("policy warning",
				"entrypoint", entrypoint,
				"ecosystem", meta.Ecosystem,
				"name", meta.Name,
				"version", meta.Version,
				"operation", meta.Operation,
				"source", warn.Source,
				"reason", warn.Reason,
			)
		}
		if deny != nil {
			RecordPolicyDeny(ctx, span, entrypoint, deny.Source, deny.Reason, meta.Ecosystem, evalDuration)
			applyPolicyHeaders(w, deny, meta)
			status := statusFromAction(deny, http.StatusForbidden)
			http.Error(w, deny.Reason, status)
			slog.Info("request denied",
				"entrypoint", entrypoint,
				"ecosystem", meta.Ecosystem,
				"name", meta.Name,
				"version", meta.Version,
				"operation", meta.Operation,
				"reason", deny.Reason,
			)
			return
		}

		// Policy allowed the request
		RecordPolicyAllow(ctx, span, entrypoint, len(warns), evalDuration)
	}

	upstream.ServeHTTP(w, r)
}
