package proxy

import (
	"context"
	"net/http"
	"strings"

	"github.com/picatz/deputy/internal/policy"
)

// PolicyEvaluator loads CEL sources and evaluates them for proxy requests.
type PolicyEvaluator interface {
	Evaluate(context.Context, string, map[string]any) ([]policy.Action, error)
}

type policyEngine struct {
	engine *policy.Engine
}

// NewPolicyEngine loads CEL policies from the provided paths.
func NewPolicyEngine(paths []string) (PolicyEvaluator, error) {
	eng, err := policy.NewEngineFromPaths(paths)
	if err != nil {
		return nil, err
	}
	return &policyEngine{engine: eng}, nil
}

func (e *policyEngine) Evaluate(ctx context.Context, entrypoint string, payload map[string]any) ([]policy.Action, error) {
	if e == nil || e.engine == nil {
		return nil, nil
	}
	if payload == nil {
		payload = map[string]any{}
	}
	env := map[string]any{
		"command":    "proxy",
		"entrypoint": entrypoint,
	}
	if existing, ok := payload["env"].(map[string]any); ok {
		for k, v := range existing {
			env[k] = v
		}
	}
	payload["env"] = env
	return e.engine.EvaluateAll(ctx, payload, "proxy", entrypoint)
}

func summarizeActions(actions []policy.Action) (deny *policy.Action, warnings []policy.Action, headers map[string]string) {
	headers = map[string]string{}
	for _, act := range actions {
		switch strings.ToLower(act.Type) {
		case "deny":
			if deny == nil {
				deny = &policy.Action{
					Source: act.Source,
					Type:   act.Type,
					Reason: firstNonEmpty(act.Reason, act.Message, "request denied by policy"),
					Status: act.Status,
				}
			}
		case "warn":
			warnings = append(warnings, act)
		case "allow":
			continue
		default:
			continue
		}
		if len(act.Headers) > 0 {
			for k, v := range act.Headers {
				headers[k] = v
			}
		}
	}
	return deny, warnings, headers
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func statusFromAction(act *policy.Action, fallback int) int {
	if act == nil {
		return fallback
	}
	if act.Status != nil && *act.Status >= 100 {
		return *act.Status
	}
	return fallback
}

type blockMeta struct {
	Ecosystem string
	Name      string
	Version   string
	Operation string
}

// applyPolicyHeaders ensures policy denies surface consistent headers for downstream tooling.
func applyPolicyHeaders(w http.ResponseWriter, act *policy.Action, meta blockMeta) {
	if w == nil || act == nil {
		return
	}
	if hdr := w.Header().Get("X-Deputy-Policy"); strings.TrimSpace(hdr) == "" {
		w.Header().Set("X-Deputy-Policy", firstNonEmpty(act.Source, "policy"))
	}
	if meta.Ecosystem != "" {
		w.Header().Set("X-Deputy-Ecosystem", meta.Ecosystem)
	}
	if meta.Name != "" {
		w.Header().Set("X-Deputy-Name", meta.Name)
	}
	if meta.Version != "" {
		w.Header().Set("X-Deputy-Version", meta.Version)
	}
	if meta.Operation != "" {
		w.Header().Set("X-Deputy-Operation", meta.Operation)
	}
	if act.Reason != "" {
		w.Header().Set("X-Deputy-Reason", act.Reason)
	}
}
