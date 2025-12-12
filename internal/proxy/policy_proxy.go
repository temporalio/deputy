package proxy

import (
	"log/slog"
	"net/http"
)

// serveWithPolicy evaluates policies for a request and, if allowed, forwards it to upstream.
//
// It applies any action headers, logs warnings/denies, and ensures deny responses include
// stable `X-Deputy-*` headers for downstream tooling.
func serveWithPolicy(w http.ResponseWriter, r *http.Request, policies PolicyEvaluator, entrypoint string, payload map[string]any, meta blockMeta, upstream http.Handler) {
	if w == nil || r == nil || upstream == nil {
		return
	}

	if policies != nil {
		actions, err := policies.Evaluate(r.Context(), entrypoint, payload)
		if err != nil {
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
	}

	upstream.ServeHTTP(w, r)
}
