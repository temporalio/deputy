package advisorysource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"connectrpc.com/connect"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	pluginv1 "github.com/temporalio/deputy/gen/deputy/plugin/v1"
	"github.com/temporalio/deputy/gen/deputy/plugin/v1/pluginv1connect"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

// fakeConnectService implements AdvisorySourceServiceHandler for an httptest
// server, proving the ConnectRPC binding end to end over real HTTP.
type fakeConnectService struct {
	got []*dependencyv1.Package
}

func (s *fakeConnectService) Info(_ context.Context, _ *connect.Request[pluginv1.AdvisorySourceInfoRequest]) (*connect.Response[pluginv1.AdvisorySourceInfoResponse], error) {
	return connect.NewResponse(&pluginv1.AdvisorySourceInfoResponse{
		Info: &pluginv1.AdvisorySourceInfo{
			Name: "remote-feed",
			Capabilities: &pluginv1.SourceCapabilities{
				Ecosystems: []string{"npm"},
				Artifacts:  []vulnerabilityv1.ArtifactKind{vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_PACKAGE},
			},
		},
	}), nil
}

func (s *fakeConnectService) Query(_ context.Context, req *connect.Request[pluginv1.AdvisoryQueryRequest]) (*connect.Response[pluginv1.AdvisoryQueryResponse], error) {
	s.got = req.Msg.GetPackages()
	return connect.NewResponse(&pluginv1.AdvisoryQueryResponse{
		Findings: []*vulnerabilityv1.Finding{
			{AdvisoryId: "FEED-1", Package: req.Msg.GetPackages()[0], Affected: true},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{"FEED-1": {Id: "FEED-1"}},
	}), nil
}

func TestConnectSourceEndToEnd(t *testing.T) {
	svc := &fakeConnectService{}
	path, handler := pluginv1connect.NewAdvisorySourceServiceHandler(svc)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	ctx := t.Context()
	src, err := NewConnectSource(ctx, server.URL)
	if err != nil {
		t.Fatalf("NewConnectSource: %v", err)
	}
	if src.Info().GetName() != "remote-feed" {
		t.Fatalf("Info name = %q, want remote-feed", src.Info().GetName())
	}

	pkg := &dependencyv1.Package{Name: "left-pad", Version: "1.0.0", Ecosystem: "npm", Purl: "pkg:npm/left-pad@1.0.0", Direct: true}
	res, err := src.Query(ctx, []*dependencyv1.Package{pkg})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(svc.got) != 1 || svc.got[0].GetPurl() != pkg.GetPurl() || !svc.got[0].GetDirect() {
		t.Fatalf("service received %+v, want the package 1:1", svc.got)
	}
	if len(res.Findings) != 1 || res.Findings[0].GetAdvisoryId() != "FEED-1" {
		t.Fatalf("findings = %+v, want FEED-1", res.Findings)
	}
	if !slices.Contains(res.Findings[0].GetSources(), "remote-feed") {
		t.Errorf("provenance not stamped: %v", res.Findings[0].GetSources())
	}

	// A connect source composes in the registry like any other source.
	reg := NewRegistry(src)
	agg, err := reg.Query(ctx, []*dependencyv1.Package{pkg})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCoverage(agg.Coverage.GetCovered(), "npm", vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_PACKAGE, "remote-feed") {
		t.Errorf("coverage missing npm by remote-feed: %+v", agg.Coverage.GetCovered())
	}
}

func TestNewConnectSourceUnreachable(t *testing.T) {
	if _, err := NewConnectSource(t.Context(), "http://127.0.0.1:1"); err == nil {
		t.Fatal("expected error for unreachable service, got nil")
	}
}

var _ Source = (*connectSource)(nil)
