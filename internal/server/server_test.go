package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	listv1 "github.com/temporalio/deputy/gen/deputy/list/v1"
	"github.com/temporalio/deputy/gen/deputy/list/v1/listv1connect"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	"github.com/temporalio/deputy/gen/deputy/scan/v1/scanv1connect"
	secretsv1 "github.com/temporalio/deputy/gen/deputy/secrets/v1"
	"github.com/temporalio/deputy/gen/deputy/secrets/v1/secretsv1connect"
)

func TestHealthEndpoint(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body, _ := io.ReadAll(rec.Body)
	if string(body) != `{"status":"ok"}` {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestReadyEndpoint(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body, _ := io.ReadAll(rec.Body)
	if string(body) != `{"status":"ready"}` {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestScanServiceRegistered(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Start test server
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create client
	client := scanv1connect.NewScanServiceClient(
		http.DefaultClient,
		ts.URL,
	)

	// Call with empty target - should return InvalidArgument error
	_, err = client.Scan(t.Context(), connect.NewRequest(&scanv1.ScanRequest{
		Target: "",
	}))

	if err == nil {
		t.Fatal("expected error for empty target")
	}

	// Check it's an InvalidArgument error
	connectErr, ok := err.(*connect.Error)
	if !ok {
		t.Fatalf("expected connect.Error, got %T", err)
	}
	if connectErr.Code() != connect.CodeInvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", connectErr.Code())
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Addr != "127.0.0.1:8090" {
		t.Errorf("expected 127.0.0.1:8090, got %s", cfg.Addr)
	}
	if cfg.ReadTimeout == 0 {
		t.Error("expected non-zero ReadTimeout")
	}
	if cfg.WriteTimeout == 0 {
		t.Error("expected non-zero WriteTimeout")
	}
	if cfg.IdleTimeout == 0 {
		t.Error("expected non-zero IdleTimeout")
	}
}

func TestNewServerWithEmptyConfig(t *testing.T) {
	// Should use defaults for empty config
	srv, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}

	if srv.Addr() != "127.0.0.1:8090" {
		t.Errorf("expected default addr 127.0.0.1:8090, got %s", srv.Addr())
	}
}

func TestVersionEndpoint(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	body, _ := io.ReadAll(rec.Body)
	if string(body) != `{"version":"v1","api":"deputy.v1"}` {
		t.Errorf("unexpected body: %s", body)
	}
}

func TestSecretsServiceRegistered(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Start test server
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create client
	client := secretsv1connect.NewSecretsServiceClient(
		http.DefaultClient,
		ts.URL,
	)

	// Call ListDetectors - should succeed
	resp, err := client.ListDetectors(t.Context(), connect.NewRequest(&secretsv1.ListDetectorsRequest{}))
	if err != nil {
		t.Fatalf("ListDetectors failed: %v", err)
	}

	// Should return at least some detectors
	if len(resp.Msg.Detectors) == 0 {
		t.Error("expected at least one detector")
	}
}

func TestSecretsServiceScanEmptyTarget(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Start test server
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create client
	client := secretsv1connect.NewSecretsServiceClient(
		http.DefaultClient,
		ts.URL,
	)

	// Call Scan with empty target - should use "." as default
	// This will fail validation for remote targets, which is expected
	_, err = client.Scan(t.Context(), connect.NewRequest(&secretsv1.ScanRequest{
		Target: "",
	}))

	// For remote server mode, empty/local paths are rejected
	if err == nil {
		t.Fatal("expected error for empty target in remote mode")
	}

	connectErr, ok := err.(*connect.Error)
	if !ok {
		t.Fatalf("expected connect.Error, got %T", err)
	}
	if connectErr.Code() != connect.CodeInvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", connectErr.Code())
	}
}

func TestListServiceRegistered(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Start test server
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create client
	client := listv1connect.NewListServiceClient(
		http.DefaultClient,
		ts.URL,
	)

	// Call ListEcosystems - should succeed
	resp, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err != nil {
		t.Fatalf("ListEcosystems failed: %v", err)
	}

	// Should return at least some ecosystems
	if len(resp.Msg.Ecosystems) == 0 {
		t.Error("expected at least one ecosystem")
	}
}

// TestAllServicesRegistered derives the procedure corpus from the services the
// server actually registers: every recorded service path maps to a proto
// service descriptor, and every method of every registered service must route
// (anything but 404). Deriving from srv.servicePaths plus the descriptors
// keeps the corpus in lockstep with server registration instead of
// hand-maintaining endpoint strings that silently go stale.
func TestAllServicesRegistered(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	// Start test server
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	procedures := registeredProcedures(t, srv)

	for _, procedure := range procedures {
		req, err := http.NewRequest(http.MethodPost, ts.URL+procedure, nil)
		if err != nil {
			t.Fatalf("failed to create request for %s: %v", procedure, err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request to %s failed: %v", procedure, err)
		}
		resp.Body.Close()

		// Should not be 404 (procedure is registered); streaming procedures
		// reject the unary content type with a non-404 status, which is fine.
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("procedure %s returned 404 - not registered", procedure)
		}
	}
}

// registeredProcedures expands the server's recorded service paths into the
// complete list of Connect procedure paths via the proto service descriptors,
// enforcing floors so an empty or shrunken registration set fails instead of
// hollowing out the callers' corpora.
func registeredProcedures(t *testing.T, srv *Server) []string {
	t.Helper()

	// Sanity floor: the server currently registers 7 services; fewer means
	// registration (or path recording) broke, not that the corpus shrank.
	if len(srv.servicePaths) < 7 {
		t.Fatalf("server recorded %d service paths, want at least 7: %v", len(srv.servicePaths), srv.servicePaths)
	}

	var procedures []string
	for _, path := range srv.servicePaths {
		name := protoreflect.FullName(strings.Trim(path, "/"))
		desc, err := protoregistry.GlobalFiles.FindDescriptorByName(name)
		if err != nil {
			t.Fatalf("registered service %q has no proto descriptor: %v", name, err)
		}
		svc, ok := desc.(protoreflect.ServiceDescriptor)
		if !ok {
			t.Fatalf("descriptor %q is %T, want a service descriptor", name, desc)
		}
		methods := svc.Methods()
		for i := range methods.Len() {
			procedures = append(procedures, path+string(methods.Get(i).Name()))
		}
	}

	// Sanity floor: 25 procedures across the registered services today.
	if len(procedures) < 25 {
		t.Fatalf("derived %d procedures, want at least 25: %v", len(procedures), procedures)
	}
	return procedures
}

// stalePolicyProcedures are procedureToEntrypoint keys that do not match any
// procedure the server registers, meaning server policies for those
// entrypoints are silently never evaluated (unknown procedures are allowed by
// default). KNOWN DEFECT, pinned rather than hidden: DiffService's real
// procedures are DiffPackages/DiffVulnerabilities/DiffContainerImages and
// GraphService's are BuildGraph/WhyDependency/QueryGraph, so the
// service_diff_request and service_graph_request entrypoints currently guard
// nothing. Fixing the map (a behavior change: those RPCs become policy
// enforced) must remove the entry here, which makes this list self-cleaning.
var stalePolicyProcedures = map[string]bool{
	"/deputy.diff.v1.DiffService/Diff":      true,
	"/deputy.graph.v1.GraphService/Resolve": true,
	"/deputy.graph.v1.GraphService/Why":     true,
}

// TestPolicyProcedureMapMatchesRegisteredProcedures checks every key of
// procedureToEntrypoint against the procedures the server actually registers.
// Procedures absent from the map bypass policy evaluation entirely, so a
// stale key silently disables authorization for that RPC. Known-stale keys
// are pinned in stalePolicyProcedures; this test fails when a new stale key
// appears or when a pinned one is fixed without unpinning it.
func TestPolicyProcedureMapMatchesRegisteredProcedures(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	registered := make(map[string]bool)
	for _, procedure := range registeredProcedures(t, srv) {
		registered[procedure] = true
	}

	for procedure := range procedureToEntrypoint {
		switch {
		case registered[procedure] && stalePolicyProcedures[procedure]:
			t.Errorf("procedure %s is registered again; remove it from stalePolicyProcedures", procedure)
		case !registered[procedure] && !stalePolicyProcedures[procedure]:
			t.Errorf("procedureToEntrypoint key %s matches no registered procedure; its policy entrypoint is silently never evaluated", procedure)
		}
	}

	for procedure := range stalePolicyProcedures {
		if _, ok := procedureToEntrypoint[procedure]; !ok {
			t.Errorf("stalePolicyProcedures entry %s is no longer in procedureToEntrypoint; remove it", procedure)
		}
	}
}
