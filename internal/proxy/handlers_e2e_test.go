package proxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	policyv1 "github.com/picatz/deputy/gen/deputy/policy/v1"
	"github.com/picatz/deputy/internal/policy"
	"google.golang.org/protobuf/proto"
)

type validatingDenyPolicy struct {
	wantEntrypoint string
	wantEcosystem  string
	wantNameKey    string
	wantName       string
	wantVersion    string
	wantOperation  string
}

func (p validatingDenyPolicy) Evaluate(_ context.Context, entrypoint string, input proto.Message) ([]policy.Action, error) {
	if entrypoint != p.wantEntrypoint {
		return nil, fmt.Errorf("entrypoint=%q want=%q", entrypoint, p.wantEntrypoint)
	}
	// Convert proto to map for validation
	payload, err := policy.ProtoToMap(input)
	if err != nil {
		return nil, fmt.Errorf("convert proto to map: %w", err)
	}
	reqAny, ok := payload["request"]
	if !ok {
		return nil, fmt.Errorf("missing payload.request")
	}
	req, ok := reqAny.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("payload.request type=%T", reqAny)
	}
	if got := fmt.Sprint(req["ecosystem"]); got != p.wantEcosystem {
		return nil, fmt.Errorf("request.ecosystem=%q want=%q", got, p.wantEcosystem)
	}
	if got := fmt.Sprint(req[p.wantNameKey]); got != p.wantName {
		return nil, fmt.Errorf("request.%s=%q want=%q", p.wantNameKey, got, p.wantName)
	}
	if got := fmt.Sprint(req["version"]); got != p.wantVersion {
		return nil, fmt.Errorf("request.version=%q want=%q", got, p.wantVersion)
	}
	if got := fmt.Sprint(req["operation"]); got != p.wantOperation {
		return nil, fmt.Errorf("request.operation=%q want=%q", got, p.wantOperation)
	}

	return []policy.Action{{
		Type:   "deny",
		Source: "policy.yaml",
		Reason: "blocked",
	}}, nil
}

func TestProxyHandlers_EndToEnd(t *testing.T) {
	tests := []struct {
		caseName     string
		newHandler   func(upstream string, policies PolicyEvaluator) (http.Handler, error)
		entrypoint   string
		path         string
		ecosystem    string
		nameKey      string
		artifactName string
		version      string
		wantOp       string
	}{
		{
			caseName:     "GoModule",
			newHandler:   NewGoModuleHandler,
			entrypoint:   "go_artifact_request",
			path:         "/github.com/acme/mod/@v/v1.2.3.mod",
			ecosystem:    "go",
			nameKey:      "module",
			artifactName: "github.com/acme/mod",
			version:      "v1.2.3",
			wantOp:       "fetch",
		},
		{
			caseName:     "NPM",
			newHandler:   NewNPMHandler,
			entrypoint:   "npm_artifact_request",
			path:         "/lodash/-/lodash-4.17.21.tgz",
			ecosystem:    "npm",
			nameKey:      "package",
			artifactName: "lodash",
			version:      "4.17.21",
			wantOp:       "download",
		},
		{
			caseName:     "PyPI",
			newHandler:   NewPyPIHandler,
			entrypoint:   "pypi_artifact_request",
			path:         "/project/requests/2.31.0/",
			ecosystem:    "pypi",
			nameKey:      "package",
			artifactName: "requests",
			version:      "2.31.0",
			wantOp:       "project",
		},
		{
			caseName:     "RubyGems",
			newHandler:   NewRubyGemsHandler,
			entrypoint:   "rubygems_artifact_request",
			path:         "/gems/rake-13.0.6.gem",
			ecosystem:    "rubygems",
			nameKey:      "package",
			artifactName: "rake",
			version:      "13.0.6",
			wantOp:       "download",
		},
	}

	for _, tt := range tests {
		t.Run(tt.caseName, func(t *testing.T) {
			var upstreamHits atomic.Int64
			var gotPath atomic.Value
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upstreamHits.Add(1)
				gotPath.Store(r.URL.Path)
				w.Header().Set("X-Upstream", "ok")
				_, _ = io.WriteString(w, "upstream-ok")
			}))
			t.Cleanup(upstream.Close)

			// Allow path: no policies, should forward to upstream.
			allowHandler, err := tt.newHandler(upstream.URL, nil)
			if err != nil {
				t.Fatalf("new handler: %v", err)
			}
			allowSrv := httptest.NewServer(allowHandler)
			t.Cleanup(allowSrv.Close)

			resp, err := allowSrv.Client().Get(allowSrv.URL + tt.path)
			if err != nil {
				t.Fatalf("allow request: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("allow status=%d body=%q", resp.StatusCode, string(body))
			}
			if got := strings.TrimSpace(string(body)); got != "upstream-ok" {
				t.Fatalf("allow body=%q", got)
			}
			if resp.Header.Get("X-Upstream") != "ok" {
				t.Fatalf("allow missing upstream header")
			}
			if got, _ := gotPath.Load().(string); got != tt.path {
				t.Fatalf("upstream path=%q want=%q", got, tt.path)
			}

			// Deny path: policy denies, must not hit upstream and should emit deputy headers.
			upstreamHits.Store(0)
			gotPath.Store("")

			denyPolicy := validatingDenyPolicy{
				wantEntrypoint: tt.entrypoint,
				wantEcosystem:  tt.ecosystem,
				wantNameKey:    tt.nameKey,
				wantName:       tt.artifactName,
				wantVersion:    tt.version,
				wantOperation:  tt.wantOp,
			}
			denyHandler, err := tt.newHandler(upstream.URL, denyPolicy)
			if err != nil {
				t.Fatalf("new handler: %v", err)
			}
			denySrv := httptest.NewServer(denyHandler)
			t.Cleanup(denySrv.Close)

			resp, err = denySrv.Client().Get(denySrv.URL + tt.path)
			if err != nil {
				t.Fatalf("deny request: %v", err)
			}
			body, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("deny status=%d body=%q", resp.StatusCode, string(body))
			}
			if upstreamHits.Load() != 0 {
				t.Fatalf("expected upstream not hit, hits=%d", upstreamHits.Load())
			}
			if resp.Header.Get("X-Deputy-Ecosystem") != tt.ecosystem {
				t.Fatalf("X-Deputy-Ecosystem=%q", resp.Header.Get("X-Deputy-Ecosystem"))
			}
			if resp.Header.Get("X-Deputy-Policy") == "" {
				t.Fatalf("missing X-Deputy-Policy header")
			}
			if tt.version != "" && resp.Header.Get("X-Deputy-Version") != tt.version {
				t.Fatalf("X-Deputy-Version=%q want=%q", resp.Header.Get("X-Deputy-Version"), tt.version)
			}
		})
	}
}

func TestProxyHandlers_DenyHeadersIncludeName(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream hit")
	}))
	t.Cleanup(upstream.Close)

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	// Use the shared reverse proxy directly to ensure deny headers are produced even when the upstream is unreachable.
	handler := newUpstreamReverseProxy(u, "test", http.DefaultTransport)
	req := httptest.NewRequest(http.MethodGet, "http://deputy.local/some/path", nil)
	rr := httptest.NewRecorder()
	testInput := &policyv1.GoArtifactRequestPolicyInput{
		Request: &policyv1.ProxyRequest{},
	}
	serveWithPolicy(rr, req, stubPolicyEvaluator{actions: []policy.Action{{Type: "deny", Source: "policy.yaml", Reason: "blocked"}}}, policy.EntrypointGoArtifactRequest, testInput, blockMeta{Ecosystem: "test", Name: "pkg", Version: "1.0.0", Operation: "fetch"}, handler)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusForbidden)
	}
	if rr.Header().Get("X-Deputy-Name") != "pkg" {
		t.Fatalf("X-Deputy-Name=%q", rr.Header().Get("X-Deputy-Name"))
	}
}
