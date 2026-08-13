package policy

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
)

// serviceRequestInput builds the policy input a given service entrypoint
// receives, naming target as the resource under request. The map is keyed by
// entrypoint and checked for completeness against EntrypointsService below, so
// mapping a new procedure to a new service entrypoint fails these tests until
// the shipped examples have an opinion about it.
//
// The builders mirror buildPolicyPayload in internal/server, which selects the
// input message by entrypoint. A diff names two resources, so both sides carry
// the requested target: these tests ask whether an entrypoint is covered at
// all, not whether each side is authorized independently, which
// TestShippedTenantIsolationAuthorizesBothDiffSides already tests.
var serviceRequestInput = map[Entrypoint]func(jwt *policyv1.JWTClaims, procedure, target string) proto.Message{
	EntrypointServiceScanRequest: func(jwt *policyv1.JWTClaims, procedure, target string) proto.Message {
		return &policyv1.ServiceScanRequestPolicyInput{
			Jwt:     jwt,
			Request: &policyv1.ServiceRequest{Procedure: procedure, Target: target},
			Env:     serviceEnv(EntrypointServiceScanRequest),
		}
	},
	EntrypointServiceListRequest: func(jwt *policyv1.JWTClaims, procedure, target string) proto.Message {
		return &policyv1.ServiceListRequestPolicyInput{
			Jwt:     jwt,
			Request: &policyv1.ServiceRequest{Procedure: procedure, Target: target},
			Env:     serviceEnv(EntrypointServiceListRequest),
		}
	},
	EntrypointServiceSBOMRequest: func(jwt *policyv1.JWTClaims, procedure, target string) proto.Message {
		return &policyv1.ServiceSbomRequestPolicyInput{
			Jwt:     jwt,
			Request: &policyv1.ServiceRequest{Procedure: procedure, Target: target},
			Env:     serviceEnv(EntrypointServiceSBOMRequest),
		}
	},
	EntrypointServiceSecretsRequest: func(jwt *policyv1.JWTClaims, procedure, target string) proto.Message {
		return &policyv1.ServiceSecretsRequestPolicyInput{
			Jwt:     jwt,
			Request: &policyv1.ServiceRequest{Procedure: procedure, Target: target},
			Env:     serviceEnv(EntrypointServiceSecretsRequest),
		}
	},
	EntrypointServiceGraphRequest: func(jwt *policyv1.JWTClaims, procedure, target string) proto.Message {
		return &policyv1.ServiceGraphRequestPolicyInput{
			Jwt:     jwt,
			Request: &policyv1.ServiceRequest{Procedure: procedure, Target: target},
			Env:     serviceEnv(EntrypointServiceGraphRequest),
		}
	},
	EntrypointServiceDiffRequest: func(jwt *policyv1.JWTClaims, procedure, target string) proto.Message {
		side := func(path string) *targetv1.Target {
			return &targetv1.Target{Kind: targetv1.TargetKind_TARGET_KIND_DIR, DisplayPath: path}
		}
		return &policyv1.ServiceDiffRequestPolicyInput{
			Jwt:        jwt,
			Request:    &policyv1.ServiceRequest{Procedure: procedure, Target: target},
			DiffBase:   side(target),
			DiffTarget: side(target),
			Env:        serviceEnv(EntrypointServiceDiffRequest),
		}
	},
}

// serviceEnv returns the environment a server-side evaluation carries.
func serviceEnv(ep Entrypoint) *policyv1.Environment {
	return &policyv1.Environment{Command: "server", Entrypoint: string(ep)}
}

// TestServiceRequestInputCoversEveryServiceEntrypoint keeps the builders above
// honest. Without it, an entrypoint missing from the map would silently drop
// out of the coverage tests below rather than failing them.
func TestServiceRequestInputCoversEveryServiceEntrypoint(t *testing.T) {
	for _, ep := range EntrypointsService {
		if _, ok := serviceRequestInput[ep]; !ok {
			t.Errorf("no policy input builder for %s: add one so the shipped service examples are tested at this entrypoint", ep)
		}
	}
	for ep := range serviceRequestInput {
		if !slices.Contains(EntrypointsService, ep) {
			t.Errorf("builder for %s, which is not a service entrypoint", ep)
		}
	}
}

// TestShippedTenantIsolationCoversEveryServiceEntrypoint tests the security
// property the multi-tenant example advertises, at every entrypoint it can be
// asked to enforce.
//
// Each policy in that file lists the entrypoints it applies to, and a rule that
// omits one simply does not run there. That made the tenant rule cover scanning
// and listing but not graph analysis, so BuildGraph, WhyDependency, and
// QueryGraph reported another tenant's dependency structure while the file read
// as though isolation were total. Enumerating EntrypointsService rather than the
// entrypoints in use today means the next mapped procedure fails here.
func TestShippedTenantIsolationCoversEveryServiceEntrypoint(t *testing.T) {
	sources, err := LoadSources([]string{findExample(t, "service-multi-tenant.yaml")})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	engine, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	for _, ep := range EntrypointsService {
		build, ok := serviceRequestInput[ep]
		if !ok {
			continue // reported by TestServiceRequestInputCoversEveryServiceEntrypoint
		}
		t.Run(string(ep), func(t *testing.T) {
			// A caller who satisfies every other rule in the file, so only the
			// tenant boundary is under test.
			jwt := &policyv1.JWTClaims{
				Sub: "user@example.com",
				CustomClaims: map[string]string{
					"tenant": "acme",
					"roles":  "[scanner security]",
					"teams":  "[security platform]",
					"scopes": "[scan sbom secrets]",
				},
			}
			input := build(jwt, "/deputy.test.v1.TestService/Probe", "github.com/other/repo")

			actions, err := engine.EvaluateAll(t.Context(), input, "server", string(ep))
			if err != nil {
				t.Fatalf("EvaluateAll: %v", err)
			}

			for _, action := range actions {
				if ActionTypeIs(action.Type, ActionDeny) {
					return
				}
			}
			t.Errorf("cross-tenant target github.com/other/repo was not denied at %s: a tenant can reach another tenant's resource through this entrypoint", ep)
		})
	}
}

// oidcIdentity is a caller shape the federation example has an opinion about.
// Each provider needs both directions tested: the untrusted identity must be
// denied at every service entrypoint, and the trusted one must be admitted.
// Testing only the deny direction is how the example came to deny everyone.
type oidcIdentity struct {
	provider string
	// trusted and untrusted differ only in the claim the gate examines.
	trusted   *policyv1.JWTClaims
	untrusted *policyv1.JWTClaims
	// admitOnly restricts the admit direction to these entrypoints. A provider
	// lists one when another rule in the file denies it for an unrelated
	// reason, which is a finding about that rule rather than about coverage.
	admitOnly []Entrypoint
	// why explains a non-empty admitOnly.
	why string
	// blocked names the defect that stops this provider being evaluated at all,
	// in either direction. Set it rather than dropping the provider, so the
	// coverage arrives on its own when the defect is fixed.
	blocked string
}

// oidcIdentities enumerates the providers the federation example gates on.
func oidcIdentities() []oidcIdentity {
	// Every service entrypoint except secrets, for the providers whose machine
	// identities human-require-mfa does not recognize as machines.
	exceptSecrets := []Entrypoint{
		EntrypointServiceScanRequest, EntrypointServiceListRequest,
		EntrypointServiceSBOMRequest, EntrypointServiceDiffRequest,
		EntrypointServiceGraphRequest,
	}
	const mfaGap = "human-require-mfa identifies machine identities by sub prefix (system:, sa:, repo:), so this provider's machine identity is treated as a human without MFA"

	return []oidcIdentity{
		{
			provider: "github-actions",
			trusted: &policyv1.JWTClaims{
				Sub: "repo:acme-corp/security-scanner:ref:refs/heads/main",
				Iss: "https://token.actions.githubusercontent.com",
				CustomClaims: map[string]string{
					"repository": "acme-corp/security-scanner", "repository_owner": "acme-corp",
					"ref": "refs/heads/main", "event_name": "push",
					"job_workflow_ref": "acme-corp/workflows/.github/workflows/security-scan.yml@refs/heads/main",
				},
			},
			untrusted: &policyv1.JWTClaims{
				Sub: "repo:untrusted-org/repo:ref:refs/heads/main",
				Iss: "https://token.actions.githubusercontent.com",
				CustomClaims: map[string]string{
					"repository": "untrusted-org/repo", "repository_owner": "untrusted-org",
					"ref": "refs/heads/main", "event_name": "push",
				},
			},
		},
		{
			provider: "gitlab-ci",
			trusted: &policyv1.JWTClaims{
				Sub:          "project_path:acme/scanner:ref_type:branch:ref:main",
				Iss:          "https://gitlab.com",
				CustomClaims: map[string]string{"namespace_path": "acme", "project_path": "acme/scanner"},
			},
			untrusted: &policyv1.JWTClaims{
				Sub:          "project_path:untrusted/repo:ref_type:branch:ref:main",
				Iss:          "https://gitlab.com",
				CustomClaims: map[string]string{"namespace_path": "untrusted", "project_path": "untrusted/repo"},
			},
			admitOnly: exceptSecrets,
			why:       mfaGap,
		},
		{
			provider: "gcp-service-account",
			trusted: &policyv1.JWTClaims{
				Sub:          "104567890123456789012",
				Iss:          "https://accounts.google.com",
				CustomClaims: map[string]string{"email": "deputy-scanner@acme-prod.iam.gserviceaccount.com"},
			},
			untrusted: &policyv1.JWTClaims{
				Sub:          "104567890123456789099",
				Iss:          "https://accounts.google.com",
				CustomClaims: map[string]string{"email": "attacker@untrusted-project.iam.gserviceaccount.com"},
			},
			admitOnly: exceptSecrets,
			why:       mfaGap,
			// A Google service account subject is a 21-digit account id, and
			// the payload conversion turns any numeric-looking string into a
			// number, so kubernetes-namespace-restriction calls .startsWith on
			// a float64 and the whole evaluation errors. The interceptor turns
			// that into CodeInternal, so this identity cannot be allowed or
			// denied, only failed.
			blocked: "#248: numeric-looking strings are coerced to numbers, so jwt.sub is a float64 for this provider",
		},
		{
			provider: "aws-sts",
			trusted: &policyv1.JWTClaims{
				Sub:          "arn:aws:sts::123456789012:assumed-role/deputy-scanner",
				CustomClaims: map[string]string{"amr": "[arn:aws:sts::123456789012:assumed-role/deputy-scanner]"},
			},
			untrusted: &policyv1.JWTClaims{
				Sub:          "arn:aws:sts::999999999999:assumed-role/attacker",
				CustomClaims: map[string]string{"amr": "[arn:aws:sts::999999999999:assumed-role/attacker]"},
			},
			admitOnly: exceptSecrets,
			why:       mfaGap,
		},
		{
			provider: "azure-ad",
			trusted: &policyv1.JWTClaims{
				Sub: "azure-user-object-id",
				Iss: "https://login.microsoftonline.com/12345678-1234-1234-1234-123456789abc/v2.0",
				CustomClaims: map[string]string{
					"tid": "12345678-1234-1234-1234-123456789abc",
					"oid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "idtyp": "app",
				},
			},
			untrusted: &policyv1.JWTClaims{
				Sub: "azure-user-object-id",
				Iss: "https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0",
				CustomClaims: map[string]string{
					"tid": "99999999-9999-9999-9999-999999999999",
					"oid": "ffffffff-ffff-ffff-ffff-ffffffffffff", "idtyp": "app",
				},
			},
			admitOnly: exceptSecrets,
			why:       mfaGap,
		},
		{
			provider: "kubernetes",
			trusted: &policyv1.JWTClaims{
				Sub:          "system:serviceaccount:security:deputy-scanner",
				CustomClaims: map[string]string{"kubernetes.io/serviceaccount/namespace": "security"},
			},
			untrusted: &policyv1.JWTClaims{
				Sub:          "system:serviceaccount:untrusted:attacker",
				CustomClaims: map[string]string{"kubernetes.io/serviceaccount/namespace": "untrusted"},
			},
		},
	}
}

// TestShippedOIDCFederationGatesEveryServiceEntrypoint tests both directions of
// every identity gate in the federation example, at every service entrypoint.
//
// The deny direction catches the coverage gap: a rule stating that only listed
// organizations, namespaces, projects, accounts, or tenants may call at all is
// not narrower when it omits an entrypoint, it is open there.
//
// The admit direction catches the opposite failure, and it is the one that went
// unnoticed. unified-identity-authorization was written as five allow rules
// followed by "deny unless anonymous". Rules do not short circuit and a deny is
// final whatever any allow says, so that catch-all fired for the trusted
// identities too and the file denied every authenticated caller. A test that
// only checks that strangers are refused passes against a policy that refuses
// everyone.
func TestShippedOIDCFederationGatesEveryServiceEntrypoint(t *testing.T) {
	sources, err := LoadSources([]string{findExample(t, "service-oidc-federation.yaml")})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	engine, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	denied := func(t *testing.T, ep Entrypoint, jwt *policyv1.JWTClaims) (bool, string) {
		t.Helper()
		build := serviceRequestInput[ep]
		input := build(jwt, "/deputy.test.v1.TestService/Probe", "github.com/acme-corp/repo")
		actions, err := engine.EvaluateAll(t.Context(), input, "server", string(ep))
		if err != nil {
			t.Fatalf("EvaluateAll: %v", err)
		}
		for _, action := range actions {
			if ActionTypeIs(action.Type, ActionDeny) {
				return true, action.Source + ": " + action.Reason
			}
		}
		return false, ""
	}

	for _, id := range oidcIdentities() {
		if id.blocked != "" {
			t.Run(id.provider, func(t *testing.T) {
				t.Skipf("cannot evaluate this provider: %s", id.blocked)
			})
			continue
		}
		for _, ep := range EntrypointsService {
			if _, ok := serviceRequestInput[ep]; !ok {
				continue
			}
			t.Run(id.provider+"/"+string(ep)+"/refuses-untrusted", func(t *testing.T) {
				if got, _ := denied(t, ep, id.untrusted); !got {
					t.Errorf("untrusted %s identity was not denied at %s: the gate for this provider does not reach this entrypoint", id.provider, ep)
				}
			})
			if len(id.admitOnly) > 0 && !slices.Contains(id.admitOnly, ep) {
				continue
			}
			t.Run(id.provider+"/"+string(ep)+"/admits-trusted", func(t *testing.T) {
				if got, by := denied(t, ep, id.trusted); got {
					t.Errorf("trusted %s identity was denied at %s by %s: a gate that refuses the callers it names is not an allowlist", id.provider, ep, by)
				}
			})
		}
		if id.why != "" {
			t.Logf("%s: admit direction not asserted at service_secrets_request, because %s", id.provider, id.why)
		}
	}
}

// TestShippedTenantIsolationRejectsUnauthorizableTargets tests the bypass that
// no amount of care in the matching expression can close.
//
// The tenant rules authorize the string a caller submitted, and a remote git
// target is not fetched as that whole string: the fragment is dropped. So
// "https://github.com/other/repo.git#/acme/x" contains "/acme/" for the
// predicate and clones other/repo.git for real. Four earlier revisions of these
// rules each fixed a different position the tenant name could hide in, which is
// the evidence that positions are the wrong thing to enumerate.
func TestShippedTenantIsolationRejectsUnauthorizableTargets(t *testing.T) {
	sources, err := LoadSources([]string{findExample(t, "service-multi-tenant.yaml")})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	engine, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	targets := []struct {
		name   string
		target string
	}{
		{"fragment naming the tenant", "https://github.com/other/repo.git#/acme/x"},
		{"query naming the tenant", "https://github.com/other/repo.git?path=/acme/x"},
	}

	for _, ep := range EntrypointsService {
		build, ok := serviceRequestInput[ep]
		if !ok {
			continue
		}
		for _, tc := range targets {
			t.Run(string(ep)+"/"+tc.name, func(t *testing.T) {
				jwt := &policyv1.JWTClaims{
					Sub: "user@example.com",
					CustomClaims: map[string]string{
						"tenant": "acme",
						"roles":  "[scanner security]",
						"teams":  "[security platform]",
						"scopes": "[scan sbom secrets]",
					},
				}
				input := build(jwt, "/deputy.test.v1.TestService/Probe", tc.target)

				actions, err := engine.EvaluateAll(t.Context(), input, "server", string(ep))
				if err != nil {
					t.Fatalf("EvaluateAll: %v", err)
				}

				for _, action := range actions {
					if ActionTypeIs(action.Type, ActionDeny) {
						return
					}
				}
				t.Errorf("target %q was not denied at %s: it satisfies the tenant predicate and names a resource another tenant owns", tc.target, ep)
			})
		}
	}
}
