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
			// AWS does not mint this token: the ARN arrives as a claim on the
			// workload's own identity provider's token, so the issuer here is
			// that provider. The fixture carried no issuer at all, which is the
			// same unrealistic shape the Kubernetes one had.
			trusted: &policyv1.JWTClaims{
				Sub:          "arn:aws:sts::123456789012:assumed-role/deputy-scanner",
				Iss:          "https://acme.okta.com",
				CustomClaims: map[string]string{"amr": "[arn:aws:sts::123456789012:assumed-role/deputy-scanner]"},
			},
			untrusted: &policyv1.JWTClaims{
				Sub:          "arn:aws:sts::999999999999:assumed-role/attacker",
				Iss:          "https://acme.okta.com",
				CustomClaims: map[string]string{"amr": "[arn:aws:sts::999999999999:assumed-role/attacker]"},
			},
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
		},
		{
			provider: "kubernetes",
			// A projected service account token carries the cluster issuer, and
			// the fixture omitted it, so pinning the subject shape to its issuer
			// broke this case before it broke any policy. A fixture that is not
			// a token a provider would actually mint cannot test a rule about
			// where tokens come from.
			trusted: &policyv1.JWTClaims{
				Sub:          "system:serviceaccount:security:deputy-scanner",
				Iss:          "https://kubernetes.default.svc.cluster.local",
				CustomClaims: map[string]string{"kubernetes.io/serviceaccount/namespace": "security"},
			},
			untrusted: &policyv1.JWTClaims{
				Sub:          "system:serviceaccount:untrusted:attacker",
				Iss:          "https://kubernetes.default.svc.cluster.local",
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
		{"dot segment leaving the tenant", "https://github.com/acme/../other/repo"},
		{"dot segments deeper in the path", "https://github.com/acme/group/../../other/repo"},
		{"percent-encoded dot segment", "https://gitlab.com/acme/%2e%2e/other/repo"},
		{"percent-encoded separator", "https://github.com/acme%2f..%2fother/repo"},
		{"trailing slash making the repository look like an owner", "https://github.com/other/acme/"},
		{"trailing slash on an SCP-style target", "git@github.com:other/acme/"},
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

// TestShippedOIDCFederationTrustsWhatItsGatesAccept tests that the unified rule
// and the per-provider gates agree about the same caller.
//
// The unified rule denies any identity matching no trusted shape, and an earlier
// version of it restated each provider's allowlist inline. Two copies of a
// trusted set drift: it trusted two GitHub organizations while
// github-actions-organization-allowlist accepted three, so a workflow from the
// third was admitted by the gate and denied by the unified rule. The branches
// now recognize a provider and leave the allowlist to that provider's own rule.
//
// The GCP branch keeps its issuer check, because a service account email is a
// name any issuer can mint, and the gcp- rules that examine the email are all
// guarded on the Google issuer. Without it, a token from any other accepted
// issuer presenting a crafted email would satisfy the unified rule while every
// gcp- rule skipped it.
func TestShippedOIDCFederationTrustsWhatItsGatesAccept(t *testing.T) {
	sources, err := LoadSources([]string{findExample(t, "service-oidc-federation.yaml")})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	engine, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	tests := []struct {
		name       string
		jwt        *policyv1.JWTClaims
		wantDenied bool
	}{
		{
			// Accepted by the organization allowlist, which names three
			// organizations. The unified rule named two.
			name: "workflow from every organization the allowlist accepts",
			jwt: &policyv1.JWTClaims{
				Sub: "repo:acme-security/scanner:ref:refs/heads/main",
				Iss: "https://token.actions.githubusercontent.com",
				CustomClaims: map[string]string{
					"repository": "acme-security/scanner", "repository_owner": "acme-security",
					"ref": "refs/heads/main", "event_name": "push",
				},
			},
			wantDenied: false,
		},
		{
			// The organization allowlist denies this one, and must keep doing
			// so now that the unified rule no longer repeats the list.
			name: "workflow from an organization the allowlist rejects",
			jwt: &policyv1.JWTClaims{
				Sub: "repo:untrusted-org/repo:ref:refs/heads/main",
				Iss: "https://token.actions.githubusercontent.com",
				CustomClaims: map[string]string{
					"repository": "untrusted-org/repo", "repository_owner": "untrusted-org",
					"ref": "refs/heads/main", "event_name": "push",
				},
			},
			wantDenied: true,
		},
		{
			// An issuer is an identity, so a substring test hands it to whoever
			// registers a matching hostname. Both the unified rule and
			// gitlab-namespace-restriction tested contains("gitlab"), so this
			// token satisfied one and was skipped by the other.
			name: "attacker-controlled issuer whose host contains a trusted name",
			jwt: &policyv1.JWTClaims{
				Sub: "project_path:acme/scanner:ref_type:branch:ref:main",
				Iss: "https://gitlab.attacker.example",
				CustomClaims: map[string]string{
					"namespace_path": "acme", "project_path": "acme/scanner",
				},
			},
			wantDenied: true,
		},
		{
			// Same shape for Azure, where the host was matched as a substring
			// and so also matched a domain merely ending in it.
			name: "issuer whose host merely ends with the Azure host",
			jwt: &policyv1.JWTClaims{
				Sub: "azure-user-object-id",
				Iss: "https://login.microsoftonline.com.attacker.example/tid/v2.0",
				CustomClaims: map[string]string{
					"tid": "12345678-1234-1234-1234-123456789abc", "idtyp": "app",
				},
			},
			wantDenied: true,
		},
		{
			// An amr entry is a claim like any other. AWS does not mint the token
			// carrying the ARN, so without an issuer test any accepted issuer
			// could assert an approved account number and be treated as a
			// machine that the secrets rules then exempt.
			name: "approved AWS account asserted by an untrusted issuer",
			jwt: &policyv1.JWTClaims{
				Sub: "arn:aws:sts::123456789012:assumed-role/deputy-scanner",
				Iss: "https://gitlab.attacker.example",
				CustomClaims: map[string]string{
					"amr": "[arn:aws:sts::123456789012:assumed-role/deputy-scanner]",
				},
			},
			wantDenied: true,
		},
		{
			// A subject prefix is a claim, so any accepted issuer able to carry
			// custom claims could present a Kubernetes subject and be treated as
			// a cluster workload. Every machine shape is now paired with the
			// issuer allowed to mint it.
			name: "Kubernetes subject minted by another issuer",
			jwt: &policyv1.JWTClaims{
				Sub: "system:serviceaccount:security:deputy-scanner",
				Iss: "https://acme.okta.com",
				CustomClaims: map[string]string{
					"kubernetes.io/serviceaccount/namespace": "security",
				},
			},
			wantDenied: true,
		},
		{
			// And the real cluster issuer still works, or the gate locks out the
			// provider it exists to admit.
			name: "Kubernetes subject from the cluster issuer",
			jwt: &policyv1.JWTClaims{
				Sub: "system:serviceaccount:security:deputy-scanner",
				Iss: "https://kubernetes.default.svc.cluster.local",
				CustomClaims: map[string]string{
					"kubernetes.io/serviceaccount/namespace": "security",
				},
			},
			wantDenied: false,
		},
		{
			// The real GitLab issuer must still be trusted, since an exact test
			// that is too strict silently locks out the provider it names.
			name: "the real GitLab issuer in a trusted namespace",
			jwt: &policyv1.JWTClaims{
				Sub: "project_path:acme/scanner:ref_type:branch:ref:main",
				Iss: "https://gitlab.com",
				CustomClaims: map[string]string{
					"namespace_path": "acme", "project_path": "acme/scanner",
				},
			},
			wantDenied: false,
		},
		{
			// A service account email is a claim, not a proof of issuer. Every
			// gcp- rule is guarded on the Google issuer, so a trusted-looking
			// email from elsewhere must not satisfy the unified rule either.
			name: "trusted-looking service account email from another issuer",
			jwt: &policyv1.JWTClaims{
				Sub: "attacker",
				Iss: "https://idp.example.com",
				CustomClaims: map[string]string{
					"email": "attacker@acme-prod.iam.gserviceaccount.com",
				},
			},
			wantDenied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Scanning, so the secrets-only rules stay out of the way.
			build := serviceRequestInput[EntrypointServiceScanRequest]
			input := build(tt.jwt, "/deputy.scan.v1.ScanService/ScanDirectory", "github.com/acme-security/scanner")
			actions, err := engine.EvaluateAll(t.Context(), input, "server", string(EntrypointServiceScanRequest))
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
				t.Errorf("denied = %v (%s), want %v", denied, by, tt.wantDenied)
			}
		})
	}
}

// TestShippedTenantIsolationAdmitsLegitimateNames tests the direction a refusal
// rule can quietly get wrong.
//
// The rule that refuses targets Deputy cannot authorize by string comparison
// searched for the characters ".." anywhere in the target, which rejects a
// repository legitimately named "repo..archive". A guard has two failure modes
// and testing what it catches says nothing about what it wrongly catches, so
// both belong here. The dot-segment test now compares whole path components.
func TestShippedTenantIsolationAdmitsLegitimateNames(t *testing.T) {
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
		{"dots inside a component", "github.com/acme/repo..archive"},
		{"a trailing dotted name", "github.com/acme/repo.archive"},
		{"a dotted namespace the tenant owns", "github.com/acme/group.v2/repo"},
		{"an ordinary repository", "github.com/acme/repo"},
		{"a tagged image the tenant owns", "ghcr.io/acme/app:v1.2.3"},
	}

	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			jwt := &policyv1.JWTClaims{
				Sub: "user@example.com",
				CustomClaims: map[string]string{
					"tenant": "acme",
					"roles":  "[scanner security]",
					"teams":  "[security platform]",
					"scopes": "[scan sbom secrets]",
				},
			}
			build := serviceRequestInput[EntrypointServiceScanRequest]
			input := build(jwt, "/deputy.scan.v1.ScanService/ScanDirectory", tc.target)
			actions, err := engine.EvaluateAll(t.Context(), input, "server", string(EntrypointServiceScanRequest))
			if err != nil {
				t.Fatalf("EvaluateAll: %v", err)
			}
			for _, action := range actions {
				if ActionTypeIs(action.Type, ActionDeny) {
					t.Errorf("target %q was denied by %s: %s. It belongs to the tenant and names the resource it fetches, so refusing it makes the example reject legitimate repositories", tc.target, action.Source, action.Reason)
				}
			}
		})
	}
}

// TestShippedOIDCFederationStillChallengesHumans tests the direction that
// widening a machine exemption can quietly break.
//
// human-require-mfa exempts identities it recognizes as machines, and the list
// of recognized shapes grew so that GitLab, Google, AWS, and Azure machine
// identities stopped being denied unconditionally at the secrets entrypoint.
// An exemption list that grows too far stops challenging the people it exists
// for, so both halves belong in a test: a human without a factor is still
// refused, and a human with one still gets through.
func TestShippedOIDCFederationStillChallengesHumans(t *testing.T) {
	sources, err := LoadSources([]string{findExample(t, "service-oidc-federation.yaml")})
	if err != nil {
		t.Fatalf("LoadSources: %v", err)
	}
	engine, err := NewEngine(sources)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	tests := []struct {
		name       string
		claims     map[string]string
		sub        string
		iss        string
		wantDenied bool
	}{
		{
			name:       "human in an authorized group without a factor",
			sub:        "alice@acme-corp.com",
			iss:        "https://acme.okta.com",
			claims:     map[string]string{"email": "alice@acme-corp.com", "groups": "[security-team]"},
			wantDenied: true,
		},
		{
			name:       "human in an authorized group with a hardware factor",
			sub:        "alice@acme-corp.com",
			iss:        "https://acme.okta.com",
			claims:     map[string]string{"email": "alice@acme-corp.com", "groups": "[security-team]", "amr": "[pwd hwk]"},
			wantDenied: false,
		},
		{
			// A subject that looks like a GitLab job but is not from GitLab must
			// not inherit the machine exemption, since the prefix is a name any
			// issuer can mint.
			name:       "GitLab-shaped subject from another issuer",
			sub:        "project_path:acme/scanner:ref_type:branch:ref:main",
			iss:        "https://acme.okta.com",
			claims:     map[string]string{"email": "attacker@acme-corp.com", "groups": "[security-team]"},
			wantDenied: true,
		},
		{
			// Same for a service account email presented by another issuer.
			name:       "service-account email from another issuer",
			sub:        "attacker",
			iss:        "https://acme.okta.com",
			claims:     map[string]string{"email": "deputy-scanner@acme-prod.iam.gserviceaccount.com", "groups": "[security-team]"},
			wantDenied: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jwt := &policyv1.JWTClaims{Sub: tt.sub, Iss: tt.iss, CustomClaims: tt.claims}
			build := serviceRequestInput[EntrypointServiceSecretsRequest]
			input := build(jwt, "/deputy.secrets.v1.SecretsService/ScanDirectory", "github.com/acme-corp/repo")
			actions, err := engine.EvaluateAll(t.Context(), input, "server", string(EntrypointServiceSecretsRequest))
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
				t.Errorf("denied = %v (%s), want %v", denied, by, tt.wantDenied)
			}
		})
	}
}
