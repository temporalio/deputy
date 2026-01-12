package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	policyv1 "github.com/picatz/deputy/gen/deputy/policy/v1"
	"github.com/picatz/deputy/internal/policy"
	"google.golang.org/protobuf/proto"
)

type stubPolicyEvaluator struct {
	actions []policy.Action
	err     error
}

func (s stubPolicyEvaluator) Evaluate(context.Context, string, proto.Message) ([]policy.Action, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.actions, nil
}

func TestServeWithPolicy(t *testing.T) {
	tests := []struct {
		name            string
		policies        PolicyEvaluator
		wantStatus      int
		wantUpstreamHit bool
		wantHeaders     map[string]string
	}{
		{
			name:            "NoPolicies_Allows",
			policies:        nil,
			wantStatus:      http.StatusOK,
			wantUpstreamHit: true,
		},
		{
			name: "Warn_AllowsAndSetsHeaders",
			policies: stubPolicyEvaluator{actions: []policy.Action{{
				Type:    "warn",
				Source:  "policy.yaml",
				Reason:  "heads up",
				Headers: map[string]string{"X-Test": "1"},
			}}},
			wantStatus:      http.StatusOK,
			wantUpstreamHit: true,
			wantHeaders:     map[string]string{"X-Test": "1"},
		},
		{
			name: "Deny_BlocksAndSetsDeputyHeaders",
			policies: stubPolicyEvaluator{actions: []policy.Action{{
				Type:   "deny",
				Source: "policy.yaml",
				Reason: "blocked",
			}}},
			wantStatus:      http.StatusForbidden,
			wantUpstreamHit: false,
			wantHeaders: map[string]string{
				"X-Deputy-Policy":      "policy.yaml",
				"X-Deputy-Ecosystem":   "go",
				"X-Deputy-Name":        "example.com/mod",
				"X-Deputy-Version":     "v1.2.3",
				"X-Deputy-Operation":   "fetch",
				"X-Deputy-Reason":      "blocked",
				"X-Deputy-Remediation": "",
			},
		},
		{
			name:            "EvaluateError_500",
			policies:        stubPolicyEvaluator{err: errors.New("boom")},
			wantStatus:      http.StatusInternalServerError,
			wantUpstreamHit: false,
		},
		{
			name: "Deny_CustomStatus",
			policies: stubPolicyEvaluator{actions: []policy.Action{{
				Type:   "deny",
				Source: "policy.yaml",
				Reason: "blocked",
				Status: ptr(451),
			}}},
			wantStatus:      451,
			wantUpstreamHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var hits atomic.Int64
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			})

			req := httptest.NewRequest(http.MethodGet, "http://deputy.local/some/path", nil)
			rr := httptest.NewRecorder()

			meta := blockMeta{
				Ecosystem: "go",
				Name:      "example.com/mod",
				Version:   "v1.2.3",
				Operation: "fetch",
			}

			serveWithPolicy(rr, req, tt.policies, policy.EntrypointGoArtifactRequest, &policyv1.GoArtifactRequestPolicyInput{}, meta, upstream)

			if rr.Code != tt.wantStatus {
				t.Fatalf("status=%d want=%d body=%q", rr.Code, tt.wantStatus, rr.Body.String())
			}
			if got := hits.Load(); (got > 0) != tt.wantUpstreamHit {
				t.Fatalf("upstreamHit=%v want=%v", got > 0, tt.wantUpstreamHit)
			}
			for k, v := range tt.wantHeaders {
				if got := rr.Header().Get(k); got != v {
					t.Fatalf("header %s=%q want=%q", k, got, v)
				}
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }
