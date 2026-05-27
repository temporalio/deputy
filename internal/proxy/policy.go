package proxy

import (
	"cmp"
	"context"
	"maps"
	"net/http"
	"strings"

	"github.com/temporalio/deputy/internal/policy"
	"google.golang.org/protobuf/proto"
)

// PolicyEvaluator is an alias for policy.Evaluator.
type PolicyEvaluator = policy.Evaluator

// proxyPolicyEngine wraps policy.Engine to inject proxy-specific context.
type proxyPolicyEngine struct {
	engine *policy.Engine
}

// NewPolicyEngine loads CEL policies from the provided paths.
// The returned Evaluator sets env.command="proxy" on all evaluations.
func NewPolicyEngine(paths []string) (policy.Evaluator, error) {
	eng, err := policy.NewEngineFromPaths(paths)
	if err != nil {
		return nil, err
	}
	return &proxyPolicyEngine{engine: eng}, nil
}

func (e *proxyPolicyEngine) Evaluate(ctx context.Context, entrypoint string, input proto.Message) ([]policy.Action, error) {
	if e == nil || e.engine == nil {
		return nil, nil
	}
	return e.engine.EvaluateAll(ctx, input, "proxy", entrypoint)
}

func summarizeActions(actions []policy.Action) (deny *policy.Action, warnings []policy.Action, headers map[string]string) {
	headers = map[string]string{}
	for _, act := range actions {
		switch strings.ToLower(act.Type) {
		case "deny":
			if deny == nil {
				deny = &policy.Action{
					Source:      act.Source,
					Type:        act.Type,
					Reason:      cmp.Or(strings.TrimSpace(act.Reason), strings.TrimSpace(act.Message), "request denied by policy"),
					Remediation: act.Remediation,
					Status:      act.Status,
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
			maps.Copy(headers, act.Headers)
		}
	}
	return deny, warnings, headers
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
		w.Header().Set("X-Deputy-Policy", cmp.Or(strings.TrimSpace(act.Source), "policy"))
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
	if act.Remediation != "" {
		w.Header().Set("X-Deputy-Remediation", act.Remediation)
	}
}
