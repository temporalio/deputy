package policy

import (
	"testing"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
)

// TestShippedTenantIsolationCoversListRequests tests that enumerating a resource
// is subject to the same tenant check as scanning it.
//
// Listing takes a target and reports what is inside it, so leaving it out of the
// isolation rule lets a tenant enumerate another tenant's repository. It was left
// out: before entrypoints were forwarded to the engine, the empty entrypoint
// disabled filtering and every rule ran on every mapped procedure, so the
// entrypoint lists in this file were never load-bearing and nothing noticed the
// omission.
func TestShippedTenantIsolationCoversListRequests(t *testing.T) {
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
			name:       "listing a resource the tenant owns",
			target:     "github.com/acme/repo",
			wantDenied: false,
		},
		{
			name:       "listing another tenant's resource",
			target:     "github.com/other/repo",
			wantDenied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &policyv1.ServiceListRequestPolicyInput{
				Jwt: &policyv1.JWTClaims{
					Sub:          "user@example.com",
					CustomClaims: map[string]string{"tenant": "acme"},
				},
				Request: &policyv1.ServiceRequest{
					Procedure: "/deputy.list.v1.ListService/ListPackages",
					Target:    tt.target,
				},
				Env: &policyv1.Environment{
					Command:    "server",
					Entrypoint: string(EntrypointServiceListRequest),
				},
			}

			actions, err := engine.EvaluateAll(t.Context(), input, "server", string(EntrypointServiceListRequest))
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

// TestShippedTenantIsolationSkipsTargetlessProcedures tests the other half of the
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

// TestShippedTenantIsolationNamesTheOwnerNotTheTag tests the bypass that folding
// ":" into a path separator opened in both tenant rules.
//
// The rules authorize a target when the tenant owns a path component, written as
// "/<tenant>/". Folding every ":" turned a tag into a component of its own, so
// "ghcr.io/other/acme:v1" read as "/ghcr.io/other/acme/v1", which contains
// "/acme/". Any image whose repository was named after a tenant passed that
// tenant's gate whoever owned it, and the attacker chose the tag that supplied
// the trailing "/". Only the separator before the first "/" is folded now.
//
// A target is a git reference, an image reference, or a directory path, and the
// deny direction is worth nothing if the fix refuses the forms the deployment
// runs on, so every form appears here in both directions. Each case runs at every
// service entrypoint, since a rule that holds at one and not another is how this
// example has failed before.
func TestShippedTenantIsolationNamesTheOwnerNotTheTag(t *testing.T) {
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
			// The bypass: the repository is named after the tenant and the tag
			// makes that name look like the namespace that owns it.
			name:       "another owner's image named after the tenant",
			target:     "ghcr.io/other/acme:v1",
			wantDenied: true,
		},
		{
			name:       "the tenant's own tagged image",
			target:     "ghcr.io/acme/app:v1",
			wantDenied: false,
		},
		{
			name:       "another owner's image behind a scheme",
			target:     "docker://ghcr.io/other/acme:v1",
			wantDenied: true,
		},
		{
			name:       "the tenant's own image behind a scheme",
			target:     "docker://ghcr.io/acme/app:v1",
			wantDenied: false,
		},
		{
			// A registry port is a ":" before the first "/", so it is folded,
			// and the tag in the same target still is not.
			name:       "another owner's image on a registry with a port",
			target:     "registry.local:5000/other/acme:v1",
			wantDenied: true,
		},
		{
			name:       "the tenant's own image on a registry with a port",
			target:     "registry.local:5000/acme/app:v1",
			wantDenied: false,
		},
		{
			name:       "another owner's image pinned by digest",
			target:     "ghcr.io/other/acme@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			wantDenied: true,
		},
		{
			name:       "the tenant's own image pinned by digest",
			target:     "ghcr.io/acme/app@sha256:0000000000000000000000000000000000000000000000000000000000000000",
			wantDenied: false,
		},
		{
			// The fold exists for this form: without it the host and the owner
			// are one component and the tenant reaches nothing it owns.
			name:       "the tenant's own SCP-style repository",
			target:     "git@github.com:acme/repo",
			wantDenied: false,
		},
		{
			name:       "another owner's SCP-style repository named after the tenant",
			target:     "git@github.com:other/acme",
			wantDenied: true,
		},
		{
			name:       "the tenant's own repository over https",
			target:     "https://github.com/acme/repo",
			wantDenied: false,
		},
		{
			name:       "another owner's repository over https",
			target:     "https://github.com/other/acme",
			wantDenied: true,
		},
		{
			name:       "a directory the tenant owns",
			target:     "/srv/tenants/acme/project",
			wantDenied: false,
		},
		{
			name:       "a directory another tenant owns",
			target:     "/srv/tenants/other/acme",
			wantDenied: true,
		},
		{
			// The tenant owning a repository named after itself must stay
			// allowed: the owner position is what matters, not the name.
			name:       "the tenant's own repository named after the tenant",
			target:     "github.com/acme/acme",
			wantDenied: false,
		},
	}

	for _, ep := range EntrypointsService {
		build, ok := serviceRequestInput[ep]
		if !ok {
			continue // reported by TestServiceRequestInputCoversEveryServiceEntrypoint
		}
		for _, tt := range tests {
			t.Run(string(ep)+"/"+tt.name, func(t *testing.T) {
				// A caller who satisfies every other rule in the file, so only
				// the tenant boundary is under test.
				jwt := &policyv1.JWTClaims{
					Sub: "user@example.com",
					CustomClaims: map[string]string{
						"tenant": "acme",
						"roles":  "[scanner security]",
						"teams":  "[security platform]",
						"scopes": "[scan sbom secrets]",
					},
				}
				input := build(jwt, "/deputy.test.v1.TestService/Probe", tt.target)

				actions, err := engine.EvaluateAll(t.Context(), input, "server", string(ep))
				if err != nil {
					t.Fatalf("EvaluateAll: %v", err)
				}

				denied, by := false, ""
				for _, action := range actions {
					if ActionTypeIs(action.Type, ActionDeny) {
						denied, by = true, action.Source+": "+action.Reason
					}
				}
				if denied != tt.wantDenied {
					t.Errorf("target %q at %s: denied = %v (%s), want %v", tt.target, ep, denied, by, tt.wantDenied)
				}
			})
		}
	}
}

// TestShippedTenantIsolationAuthorizesBothDiffSides tests the security property
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
			// The tag fold again, on the side request.target does not report:
			// "ghcr.io/other/acme:v1" read as "/ghcr.io/other/acme/v1", so the
			// repository name passed for the namespace that owns it.
			name:       "another owner's image whose repository is named after the tenant",
			tenant:     "acme",
			base:       "ghcr.io/acme/app:v1",
			target:     "ghcr.io/other/acme:v1",
			wantDenied: true,
		},
		{
			name:       "SCP-style repository named after the tenant, with a ref-like suffix",
			tenant:     "acme",
			base:       "git@github.com:acme/repo",
			target:     "git@github.com:other/acme:v1",
			wantDenied: true,
		},
		{
			name:       "a directory another tenant owns, named after the tenant",
			tenant:     "acme",
			base:       "/srv/tenants/acme/project",
			target:     "/srv/tenants/other/acme:v1",
			wantDenied: true,
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
				DiffBase:   side(tt.base),
				DiffTarget: side(tt.target),
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
