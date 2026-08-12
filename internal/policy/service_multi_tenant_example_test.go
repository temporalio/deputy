package policy

import (
	"testing"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
)

// TestShippedTenantIsolationAuthorizesBothDiffSides pins the security property
// of the shipped multi-tenant example, which operators are invited to copy.
//
// The example's original tenant-isolation rule covered service_diff_request but
// checked only request.target. That field reports the base side of a diff, so an
// authorized base carried an arbitrary target and the rule read as isolation
// while permitting a cross-tenant read. The lookalike cases below matter just as
// much: a substring test admits a longer tenant name, and interpolating the
// claim into a regex lets a claim containing metacharacters match a path that
// belongs to someone else.
func TestShippedTenantIsolationAuthorizesBothDiffSides(t *testing.T) {
	sources, err := LoadSources([]string{findExample(t, "service-multi-tenant.yaml")})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	engine, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	tests := []struct {
		name       string
		tenant     string
		base       string
		target     string
		wantDenied bool
	}{
		{
			name:       "both sides in the tenant namespace",
			tenant:     "acme",
			base:       "github.com/acme/repo",
			target:     "github.com/acme/other",
			wantDenied: false,
		},
		{
			// The case the base-only check missed.
			name:       "authorized base paired with another tenant's target",
			tenant:     "acme",
			base:       "github.com/acme/repo",
			target:     "github.com/other/repo",
			wantDenied: true,
		},
		{
			name:       "another tenant's base paired with an authorized target",
			tenant:     "acme",
			base:       "github.com/other/repo",
			target:     "github.com/acme/repo",
			wantDenied: true,
		},
		{
			// A substring test would admit this, since "acme" occurs in the
			// longer component.
			name:       "tenant name is a prefix of the path component",
			tenant:     "acme",
			base:       "github.com/acme-corp-archive/repo",
			target:     "github.com/acme-corp-archive/repo",
			wantDenied: true,
		},
		{
			// Interpolating the claim into a regex would admit this, since "."
			// matches any character.
			name:       "claim containing a regex metacharacter",
			tenant:     "acme.com",
			base:       "github.com/acmeXcom/repo",
			target:     "github.com/acmeXcom/repo",
			wantDenied: true,
		},
		{
			// An omitted side must fail the allowlist rather than pass it.
			name:       "empty base side",
			tenant:     "acme",
			base:       "",
			target:     "github.com/acme/repo",
			wantDenied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			side := func(path string) *targetv1.Target {
				return &targetv1.Target{
					Kind:        targetv1.TargetKind_TARGET_KIND_DIR,
					DisplayPath: path,
				}
			}
			input := &policyv1.ServiceDiffRequestPolicyInput{
				Jwt: &policyv1.JWTClaims{
					Sub:          "user@example.com",
					CustomClaims: map[string]string{"tenant": tt.tenant},
				},
				Request: &policyv1.ServiceRequest{
					Procedure: "/deputy.diff.v1.DiffService/DiffPackages",
					// Reports the base side, which is exactly why a diff
					// policy cannot rely on it.
					Target: tt.base,
				},
				BaseTarget:   side(tt.base),
				TargetTarget: side(tt.target),
				Env: &policyv1.Environment{
					Command:    "server",
					Entrypoint: string(EntrypointServiceDiffRequest),
				},
			}

			actions, err := engine.EvaluateAll(t.Context(), input, "server", string(EntrypointServiceDiffRequest))
			if err != nil {
				t.Fatalf("EvaluateAll: %v", err)
			}

			denied := false
			var reason string
			for _, action := range actions {
				if ActionTypeIs(action.Type, ActionDeny) {
					denied = true
					reason = action.Reason
				}
			}
			if denied != tt.wantDenied {
				t.Errorf("denied = %v (reason %q), want %v", denied, reason, tt.wantDenied)
			}
		})
	}
}
