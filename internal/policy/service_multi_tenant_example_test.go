package policy

import (
	"testing"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
)

// TestShippedTenantIsolationSkipsTargetlessProcedures pins the other half of the
// contract: several procedures the single-target rule covers name no resource at
// all (SecretsService Verify, ListDetectors, RegisterDetector, and SBOMService
// Diff), so request.target is empty for them. A tenant rule that treats an empty
// target as failing its allowlist denies those operations unconditionally, which
// is how an isolation rule turns into an outage. They are governed by
// require-tenant-claim and secrets-requires-security-team instead.
func TestShippedTenantIsolationSkipsTargetlessProcedures(t *testing.T) {
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
		target     string
		wantDenied bool
	}{
		{
			name:       "procedure that names no resource",
			target:     "",
			wantDenied: false,
		},
		{
			name:       "resource inside the tenant namespace",
			target:     "github.com/acme/repo",
			wantDenied: false,
		},
		{
			name:       "resource belonging to another tenant",
			target:     "github.com/other/repo",
			wantDenied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Only the tenant rule is under test, so the caller satisfies every
			// other rule in the file.
			input := &policyv1.ServiceSbomRequestPolicyInput{
				Jwt: &policyv1.JWTClaims{
					Sub:          "user@example.com",
					CustomClaims: map[string]string{"tenant": "acme"},
				},
				Request: &policyv1.ServiceRequest{
					Procedure: "/deputy.sbom.v1.SBOMService/Diff",
					Target:    tt.target,
				},
				Env: &policyv1.Environment{
					Command:    "server",
					Entrypoint: string(EntrypointServiceSBOMRequest),
				},
			}

			actions, err := engine.EvaluateAll(t.Context(), input, "server", string(EntrypointServiceSBOMRequest))
			if err != nil {
				t.Fatalf("EvaluateAll: %v", err)
			}

			denied := false
			var by string
			for _, action := range actions {
				if ActionTypeIs(action.Type, ActionDeny) {
					denied = true
					by = action.Source
				}
			}
			if denied != tt.wantDenied {
				t.Errorf("denied = %v (by %s), want %v", denied, by, tt.wantDenied)
			}
		})
	}
}

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
			// An omitted side must fail the allowlist rather than pass it. A
			// diff always names two resources, so a missing one is malformed,
			// unlike the targetless procedures covered by the single-target
			// rule.
			name:       "empty base side",
			tenant:     "acme",
			base:       "",
			target:     "github.com/acme/repo",
			wantDenied: true,
		},
		{
			// SCP-style git targets are reachable when SSH egress is allowed.
			// Splitting on "/" alone leaves "git@github.com:acme", which denied
			// the tenant its own repositories.
			name:       "SCP-style targets in the tenant namespace",
			tenant:     "acme",
			base:       "git@github.com:acme/repo",
			target:     "git@github.com:acme/other",
			wantDenied: false,
		},
		{
			name:       "SCP-style target belonging to another tenant",
			tenant:     "acme",
			base:       "git@github.com:acme/repo",
			target:     "git@github.com:other/repo",
			wantDenied: true,
		},
		{
			// Accepting the tenant as any path component authorized this: the
			// repository someone else owns is merely named after the tenant.
			name:       "another owner's repository named after the tenant",
			tenant:     "acme",
			base:       "github.com/acme/repo",
			target:     "github.com/other/acme",
			wantDenied: true,
		},
		{
			// Same bypass through an image tag, which folding ":" turns into a
			// component of its own.
			name:       "another owner's image tagged with the tenant name",
			tenant:     "acme",
			base:       "ghcr.io/acme/app:v1",
			target:     "ghcr.io/other/app:acme",
			wantDenied: true,
		},
		{
			name:       "tagged images the tenant owns",
			tenant:     "acme",
			base:       "ghcr.io/acme/app:v1",
			target:     "ghcr.io/acme/app:v2",
			wantDenied: false,
		},
		{
			name:       "nested namespace the tenant owns",
			tenant:     "acme",
			base:       "github.com/acme/group/repo",
			target:     "github.com/acme/other/repo",
			wantDenied: false,
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
