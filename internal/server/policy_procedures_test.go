package server

import (
	"context"
	"maps"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	"github.com/temporalio/deputy/gen/deputy/diff/v1/diffv1connect"
	"github.com/temporalio/deputy/gen/deputy/graph/v1/graphv1connect"
	"github.com/temporalio/deputy/gen/deputy/list/v1/listv1connect"
	"github.com/temporalio/deputy/gen/deputy/sbom/v1/sbomv1connect"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	"github.com/temporalio/deputy/gen/deputy/scan/v1/scanv1connect"
	"github.com/temporalio/deputy/gen/deputy/secrets/v1/secretsv1connect"
	"github.com/temporalio/deputy/internal/policy"
)

// policyBearingServices pairs each Connect service that the server registers
// with the service_*_request entrypoint that authorizes it. Every procedure of
// these services must appear in procedureToEntrypoint, because policyInterceptor
// allows anything it cannot find.
var policyBearingServices = []struct {
	name       string
	entrypoint policy.Entrypoint
}{
	{scanv1connect.ScanServiceName, policy.EntrypointServiceScanRequest},
	{listv1connect.ListServiceName, policy.EntrypointServiceListRequest},
	{sbomv1connect.SBOMServiceName, policy.EntrypointServiceSBOMRequest},
	{diffv1connect.DiffServiceName, policy.EntrypointServiceDiffRequest},
	{secretsv1connect.SecretsServiceName, policy.EntrypointServiceSecretsRequest},
	{graphv1connect.GraphServiceName, policy.EntrypointServiceGraphRequest},
}

// serviceDescriptor resolves a fully qualified service name against the global
// proto registry, so tests compare procedure maps to the protos themselves
// rather than to a second hand-written list.
func serviceDescriptor(t *testing.T, name string) protoreflect.ServiceDescriptor {
	t.Helper()

	desc, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		t.Fatalf("resolve service %s: %v", name, err)
	}
	service, ok := desc.(protoreflect.ServiceDescriptor)
	if !ok {
		t.Fatalf("descriptor %s is a %T, want a service", name, desc)
	}
	return service
}

// procedurePath renders the Connect procedure path for a proto method, which is
// the form policyInterceptor sees in connect.Spec.Procedure.
func procedurePath(service protoreflect.ServiceDescriptor, method protoreflect.MethodDescriptor) string {
	return "/" + string(service.FullName()) + "/" + string(method.Name())
}

// TestPolicyProcedureKeysAreRealProcedures checks that every key in
// procedureToEntrypoint names a method that actually exists on its service.
// Using the generated Connect constants makes this structurally true today,
// but a future hand-written key would reintroduce the defect this test guards:
// a key that matches no procedure is dead weight, and the entrypoint it claims
// to guard is never evaluated.
func TestPolicyProcedureKeysAreRealProcedures(t *testing.T) {
	procedures := slices.Sorted(maps.Keys(procedureToEntrypoint))

	for _, procedure := range procedures {
		t.Run(procedure, func(t *testing.T) {
			serviceName, methodName, ok := strings.Cut(strings.TrimPrefix(procedure, "/"), "/")
			if !ok {
				t.Fatalf("procedure %q is not in /package.Service/Method form", procedure)
			}

			service := serviceDescriptor(t, serviceName)
			if service.Methods().ByName(protoreflect.Name(methodName)) == nil {
				t.Errorf("service %s has no method %s, so entrypoint %s is never evaluated for this key",
					serviceName, methodName, procedureToEntrypoint[procedure])
			}
		})
	}
}

// TestPolicyBearingServiceProceduresAreMapped checks the security-relevant
// direction: every procedure of a service that declares a service_*_request
// entrypoint is mapped, to that entrypoint. Unmapped procedures are allowed
// without evaluating any policy, so a gap here means the entrypoint guards
// less than its name suggests. The expectation comes from the proto
// descriptors, so adding an RPC without mapping it fails here.
func TestPolicyBearingServiceProceduresAreMapped(t *testing.T) {
	for _, svc := range policyBearingServices {
		t.Run(svc.name, func(t *testing.T) {
			service := serviceDescriptor(t, svc.name)
			methods := service.Methods()
			if methods.Len() == 0 {
				t.Fatalf("service %s declares no methods; the expectation would be vacuous", svc.name)
			}

			for i := range methods.Len() {
				method := methods.Get(i)
				procedure := procedurePath(service, method)

				mapped, ok := procedureToEntrypoint[procedure]
				if !ok {
					t.Errorf("procedure %s is unmapped, so %s is never evaluated and the RPC is authorized by nothing",
						procedure, svc.entrypoint)
					continue
				}
				if mapped != svc.entrypoint {
					t.Errorf("procedure %s maps to %s, want %s", procedure, mapped, svc.entrypoint)
				}
			}
		})
	}
}

// TestPolicyBearingServicesCoverServiceEntrypoints keeps the table above honest:
// every service_*_request entrypoint must be claimed by a registered service,
// otherwise a new entrypoint could ship with no procedures behind it and the
// coverage test above would still pass.
func TestPolicyBearingServicesCoverServiceEntrypoints(t *testing.T) {
	claimed := make(map[policy.Entrypoint]bool, len(policyBearingServices))
	for _, svc := range policyBearingServices {
		claimed[svc.entrypoint] = true
	}

	for _, entrypoint := range policy.EntrypointsService {
		if !claimed[entrypoint] {
			t.Errorf("service entrypoint %s is claimed by no service in policyBearingServices, so nothing checks that its procedures are mapped", entrypoint)
		}
	}
}

// writePolicyFile writes a policy document to a temp file and returns its path.
func writePolicyFile(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return path
}

// denyPolicy renders a policy document with one always-firing deny rule,
// optionally scoped to the given entrypoints. No entrypoints means the policy
// declares none and therefore applies everywhere.
func denyPolicy(name, when string, entrypoints ...policy.Entrypoint) string {
	var b strings.Builder
	b.WriteString("policies:\n")
	b.WriteString("  - name: " + name + "\n")
	if len(entrypoints) > 0 {
		b.WriteString("    entrypoints:\n")
		for _, entrypoint := range entrypoints {
			b.WriteString("      - " + entrypoint.String() + "\n")
		}
	}
	b.WriteString("    rules:\n")
	b.WriteString("      - action: deny\n")
	b.WriteString("        when: \"" + when + "\"\n")
	b.WriteString("        reason: \"denied by " + name + "\"\n")
	return b.String()
}

// TestServicePolicyEnforcement pins the two behavior changes that have to ship
// together. Mapping the real DiffService procedures makes DiffPackages evaluate
// service_diff_request, and forwarding that entrypoint to the engine keeps a
// policy scoped to some other entrypoint from firing on it. Without the second
// change, mapping twelve more procedures would start firing every loaded policy
// on RPCs it never touched.
//
// Each request is deliberately empty, so a request that clears policy fails in
// the handler with invalid_argument. That code therefore means "reached the
// handler exactly as before", and permission_denied means a policy fired.
func TestServicePolicyEnforcement(t *testing.T) {
	diffPackages := func(t *testing.T, ts *httptest.Server) error {
		t.Helper()
		client := diffv1connect.NewDiffServiceClient(ts.Client(), ts.URL)
		_, err := client.DiffPackages(context.Background(), connect.NewRequest(&diffv1.DiffPackagesRequest{}))
		return err
	}
	scan := func(t *testing.T, ts *httptest.Server) error {
		t.Helper()
		client := scanv1connect.NewScanServiceClient(ts.Client(), ts.URL)
		_, err := client.Scan(context.Background(), connect.NewRequest(&scanv1.ScanRequest{}))
		return err
	}

	denyDiff := denyPolicy("deny-diff", "true", policy.EntrypointServiceDiffRequest)
	denyScan := denyPolicy("deny-scan", "true", policy.EntrypointServiceScanRequest)
	denyNothing := denyPolicy("deny-nothing", "false", policy.EntrypointServiceDiffRequest)
	denyEverywhere := denyPolicy("deny-everywhere", "true")

	tests := []struct {
		name     string
		policy   string
		call     func(*testing.T, *httptest.Server) error
		wantCode connect.Code
	}{
		{
			name:     "diff with no policies loaded",
			call:     diffPackages,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "diff with a policy that denies nothing",
			policy:   denyNothing,
			call:     diffPackages,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "diff with a diff policy is now enforced",
			policy:   denyDiff,
			call:     diffPackages,
			wantCode: connect.CodePermissionDenied,
		},
		{
			name:     "diff with a scan policy does not fire",
			policy:   denyScan,
			call:     diffPackages,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			name:     "diff with an unscoped policy still fires",
			policy:   denyEverywhere,
			call:     diffPackages,
			wantCode: connect.CodePermissionDenied,
		},
		{
			name:     "scan with a scan policy stays enforced",
			policy:   denyScan,
			call:     scan,
			wantCode: connect.CodePermissionDenied,
		},
		{
			name:     "scan with a diff policy does not fire",
			policy:   denyDiff,
			call:     scan,
			wantCode: connect.CodeInvalidArgument,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			if tt.policy != "" {
				cfg.Policies = []string{writePolicyFile(t, tt.policy)}
			}

			srv, err := New(cfg)
			if err != nil {
				t.Fatalf("new server: %v", err)
			}
			ts := httptest.NewServer(srv.Handler())
			defer ts.Close()

			err = tt.call(t, ts)
			if err == nil {
				t.Fatal("request succeeded, want an error")
			}
			if got := connect.CodeOf(err); got != tt.wantCode {
				t.Errorf("request returned code %v (%v), want %v", got, err, tt.wantCode)
			}
		})
	}
}
