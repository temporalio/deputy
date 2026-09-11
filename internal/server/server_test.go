package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
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
	"github.com/temporalio/deputy/internal/policy"
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

// registeredService is a ConnectRPC service the server registers, paired with
// the policy entrypoint that must authorize it. authorized is false for a
// service that has no service entrypoint of its own, which is a legitimate
// state (RemediationService) and not the same thing as a missing mapping.
type registeredService struct {
	// procedures are the service's full Connect procedure paths, each already
	// prefixed with the service's URL path.
	procedures []string
	// entrypoint authorizes every procedure of the service.
	entrypoint policy.Entrypoint
	// authorized reports whether entrypoint is set.
	authorized bool
}

// serviceEntrypoint derives the policy entrypoint that authorizes a proto
// service from its package segment: deputy.scan.v1.ScanService is authorized
// by service_scan_request. It reports false when the derived name is not a
// real service entrypoint, which keeps the derivation honest in both
// directions: a service with no authorization surface is recognized as such,
// and a future service whose package diverges from its entrypoint name is
// caught by the coverage check over policy.EntrypointsService.
func serviceEntrypoint(name protoreflect.FullName) (policy.Entrypoint, bool) {
	parts := strings.Split(string(name), ".")
	if len(parts) < 3 {
		return "", false
	}
	candidate := policy.Entrypoint("service_" + parts[1] + "_request")
	if !slices.Contains(policy.EntrypointsService, candidate) {
		return "", false
	}
	return candidate, true
}

// registeredServices expands the server's recorded service paths into proto
// service descriptors, their full procedure paths, and the policy entrypoint
// that must authorize each, enforcing floors so an empty or shrunken
// registration set fails instead of hollowing out the callers' corpora.
func registeredServices(t *testing.T, srv *Server) []registeredService {
	t.Helper()

	// Sanity floor: the server currently registers 7 services; fewer means
	// registration (or path recording) broke, not that the corpus shrank.
	if len(srv.servicePaths) < 7 {
		t.Fatalf("server recorded %d service paths, want at least 7: %v", len(srv.servicePaths), srv.servicePaths)
	}

	services := make([]registeredService, 0, len(srv.servicePaths))
	total := 0
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

		entrypoint, authorized := serviceEntrypoint(name)
		service := registeredService{entrypoint: entrypoint, authorized: authorized}
		methods := svc.Methods()
		for i := range methods.Len() {
			service.procedures = append(service.procedures, path+string(methods.Get(i).Name()))
		}
		total += len(service.procedures)
		services = append(services, service)
	}

	// Sanity floor: 25 procedures across the registered services today.
	if total < 25 {
		t.Fatalf("derived %d procedures across %d services, want at least 25", total, len(services))
	}
	return services
}

// registeredProcedures is the flat list of Connect procedure paths the server
// registers, derived from registeredServices.
func registeredProcedures(t *testing.T, srv *Server) []string {
	t.Helper()

	var procedures []string
	for _, service := range registeredServices(t, srv) {
		procedures = append(procedures, service.procedures...)
	}
	return procedures
}

// TestPolicyProcedureMapMatchesRegisteredProcedures checks procedureToEntrypoint
// against the procedures the server registers, in both directions, because
// each direction hides a different defect.
//
// Outward: a key that matches no registered procedure is dead weight and its
// entrypoint is never evaluated.
//
// Inward, and this is the security-relevant direction: unknown procedures are
// allowed by default, so a procedure of a policy-bearing service that the map
// omits is authorized by nothing. The expectation is derived rather than
// hand-pinned, by crossing the registered services with the service
// entrypoints in policy.EntrypointsService, so deleting or renaming a live
// mapping fails here instead of silently disabling enforcement.
func TestPolicyProcedureMapMatchesRegisteredProcedures(t *testing.T) {
	srv, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}

	services := registeredServices(t, srv)

	registered := make(map[string]bool)
	expected := make(map[string]policy.Entrypoint)
	claimed := make(map[policy.Entrypoint]bool)
	for _, service := range services {
		for _, procedure := range service.procedures {
			registered[procedure] = true
			if service.authorized {
				expected[procedure] = service.entrypoint
			}
		}
		if service.authorized {
			claimed[service.entrypoint] = true
		}
	}

	// Every service entrypoint must belong to some registered service. An
	// unclaimed one means the entrypoint is unreachable, or that a service
	// package no longer matches its entrypoint name and so dropped out of the
	// derived expectation below without anything noticing.
	for _, entrypoint := range policy.EntrypointsService {
		if !claimed[entrypoint] {
			t.Errorf("service entrypoint %s is claimed by no registered service; the derived authorization expectation cannot cover it", entrypoint)
		}
	}

	// Sanity floor: 19 procedures across the six policy-bearing services
	// today. A collapsed expectation would make the inward check vacuous.
	if len(expected) < 19 {
		t.Fatalf("derived %d procedures needing authorization, want at least 19", len(expected))
	}

	// Inward: every procedure that should be authorized is mapped, to the
	// right entrypoint.
	for procedure, entrypoint := range expected {
		mapped, ok := procedureToEntrypoint[procedure]
		switch {
		case !ok:
			t.Errorf("registered procedure %s has no procedureToEntrypoint mapping, so %s is never evaluated and the RPC is authorized by nothing", procedure, entrypoint)
		case mapped != entrypoint:
			t.Errorf("procedure %s maps to entrypoint %s, want %s derived from its service package", procedure, mapped, entrypoint)
		}
	}

	// Outward: every key names a procedure the server registers.
	for procedure := range procedureToEntrypoint {
		if !registered[procedure] {
			t.Errorf("procedureToEntrypoint key %s matches no registered procedure; its policy entrypoint is silently never evaluated", procedure)
		}
	}
}
