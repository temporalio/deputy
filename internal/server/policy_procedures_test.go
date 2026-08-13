package server

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	"github.com/temporalio/deputy/gen/deputy/diff/v1/diffv1connect"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	"github.com/temporalio/deputy/gen/deputy/scan/v1/scanv1connect"
	"github.com/temporalio/deputy/internal/policy"
)

// TestBuildPolicyPayloadCarriesBothDiffSides tests that a diff policy sees each
// side of the comparison as the caller sent it. The two sides are independent
// resources, so collapsing them lets a caller pair an authorized base with an
// unauthorized target and have the policy authorize the base twice, and
// dropping them entirely leaves the policy with nothing to match on.
func TestBuildPolicyPayloadCarriesBothDiffSides(t *testing.T) {
	tests := []struct {
		name       string
		request    connect.AnyRequest
		wantBase   string
		wantTarget string
	}{
		{
			name:       "diff packages",
			request:    connect.NewRequest(&diffv1.DiffPackagesRequest{BaseTarget: "base-repo", TargetTarget: "target-repo"}),
			wantBase:   "base-repo",
			wantTarget: "target-repo",
		},
		{
			name:       "diff vulnerabilities",
			request:    connect.NewRequest(&diffv1.DiffVulnerabilitiesRequest{BaseTarget: "base-repo", TargetTarget: "target-repo"}),
			wantBase:   "base-repo",
			wantTarget: "target-repo",
		},
		{
			name:       "diff container images",
			request:    connect.NewRequest(&diffv1.DiffContainerImagesRequest{BaseImage: "base-image", TargetImage: "target-image"}),
			wantBase:   "base-image",
			wantTarget: "target-image",
		},
		{
			// An omitted side is still bound, as an empty display path, so a
			// policy referencing it denies instead of failing to evaluate.
			name:       "diff with only a base",
			request:    connect.NewRequest(&diffv1.DiffPackagesRequest{BaseTarget: "base-repo"}),
			wantBase:   "base-repo",
			wantTarget: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := buildPolicyPayload(context.Background(), tt.request, policy.EntrypointServiceDiffRequest)

			input, ok := payload.(*policyv1.ServiceDiffRequestPolicyInput)
			if !ok {
				t.Fatalf("payload is a %T, want *policyv1.ServiceDiffRequestPolicyInput", payload)
			}
			// Both sides must be bound, not merely read as empty: an unset
			// message is stripped from the CEL activation, which turns every
			// policy that mentions it into an evaluation error.
			if input.GetBaseTarget() == nil {
				t.Error("base_target is unset, want it bound even when the caller omits it")
			}
			if input.GetTargetTarget() == nil {
				t.Error("target_target is unset, want it bound even when the caller omits it")
			}
			if got := input.GetBaseTarget().GetDisplayPath(); got != tt.wantBase {
				t.Errorf("base_target.display_path = %q, want %q", got, tt.wantBase)
			}
			if got := input.GetTargetTarget().GetDisplayPath(); got != tt.wantTarget {
				t.Errorf("target_target.display_path = %q, want %q", got, tt.wantTarget)
			}
		})
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

// commandScopedDenyPolicy builds a policy that declares commands: but no
// entrypoints:, the shape a shared bundle written for the CLI has. Such a policy
// must be filtered by command alone.
func commandScopedDenyPolicy(name, when string, commands ...string) string {
	var b strings.Builder
	b.WriteString("policies:\n")
	b.WriteString("  - name: " + name + "\n")
	b.WriteString("    commands:\n")
	for _, command := range commands {
		b.WriteString("      - " + command + "\n")
	}
	b.WriteString("    rules:\n")
	b.WriteString("      - action: deny\n")
	b.WriteString("        when: \"" + when + "\"\n")
	b.WriteString("        reason: \"denied by " + name + "\"\n")
	return b.String()
}

// TestServicePolicyEnforcement tests the two behavior changes that have to ship
// together. Mapping the real DiffService procedures makes DiffPackages evaluate
// service_diff_request, and forwarding that entrypoint to the engine keeps a
// policy scoped to some other entrypoint from firing on it. Without the second
// change, mapping twelve more procedures would start firing every loaded policy
// on RPCs it never touched.
//
// No request here can succeed, which is what makes the codes legible.
// permission_denied means a policy fired. Any other code means the request
// cleared policy and failed inside the handler: invalid_argument for an empty
// request, and internal for one whose targets are non-empty but unresolvable.
func TestServicePolicyEnforcement(t *testing.T) {
	diffPackagesBetween := func(base, target string) func(*testing.T, *httptest.Server) error {
		return func(t *testing.T, ts *httptest.Server) error {
			t.Helper()
			client := diffv1connect.NewDiffServiceClient(ts.Client(), ts.URL)
			_, err := client.DiffPackages(context.Background(), connect.NewRequest(&diffv1.DiffPackagesRequest{
				BaseTarget:   base,
				TargetTarget: target,
			}))
			return err
		}
	}
	diffPackages := diffPackagesBetween("", "")
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
	denyBaseSide := denyPolicy("deny-base-side", "base_target.display_path == 'forbidden'", policy.EntrypointServiceDiffRequest)
	denyTargetSide := denyPolicy("deny-target-side", "target_target.display_path == 'forbidden'", policy.EntrypointServiceDiffRequest)

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
			// The target side is authorized independently, so a forbidden
			// target cannot ride along with an allowed base.
			name:     "diff with a forbidden target side is denied",
			policy:   denyTargetSide,
			call:     diffPackagesBetween("allowed", "forbidden"),
			wantCode: connect.CodePermissionDenied,
		},
		{
			name:     "diff with a forbidden base side is denied",
			policy:   denyBaseSide,
			call:     diffPackagesBetween("forbidden", "allowed"),
			wantCode: connect.CodePermissionDenied,
		},
		{
			// The sharp anti-conflation case. A target-side policy must not
			// fire on the base value: when the two sides were collapsed, this
			// request was denied for a target that is allowed.
			name:     "diff with a forbidden base does not trip a target-side policy",
			policy:   denyTargetSide,
			call:     diffPackagesBetween("forbidden", "allowed"),
			wantCode: connect.CodeInternal,
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
		{
			// A CLI-scoped policy in a shared bundle must not reach server
			// RPCs. Passing no command disabled this filter, so the policy
			// below fired on every mapped procedure.
			name:     "diff with a policy scoped to the scan command does not fire",
			policy:   commandScopedDenyPolicy("deny-scan-command", "true", "scan"),
			call:     diffPackages,
			wantCode: connect.CodeInvalidArgument,
		},
		{
			// The other direction, so the case above cannot pass merely because
			// command filtering rejects everything.
			name:     "diff with a policy scoped to the server command fires",
			policy:   commandScopedDenyPolicy("deny-server-command", "true", "server"),
			call:     diffPackages,
			wantCode: connect.CodePermissionDenied,
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
