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

// TestShippedOIDCFederationCoversEveryServiceEntrypoint tests the same class of
// gap in the federation example, whose identity rules state that only listed
// organizations, namespaces, projects, accounts, and tenants may call at all.
//
// A rule of that kind that omits an entrypoint is not a narrower rule, it is an
// unauthenticated hole: the untrusted identity is denied for scanning and
// admitted for the entrypoints the rule forgot.
func TestShippedOIDCFederationCoversEveryServiceEntrypoint(t *testing.T) {
	sources, err := LoadSources([]string{findExample(t, "service-oidc-federation.yaml")})
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
			continue
		}
		t.Run(string(ep), func(t *testing.T) {
			// A GitHub Actions token from an organization the file does not
			// trust. Every other claim is well formed, so only the
			// organization allowlist can be what denies it.
			jwt := &policyv1.JWTClaims{
				Sub: "repo:untrusted-org/repo:ref:refs/heads/main",
				Iss: "https://token.actions.githubusercontent.com",
				CustomClaims: map[string]string{
					"repository":       "untrusted-org/repo",
					"repository_owner": "untrusted-org",
					"ref":              "refs/heads/main",
					"event_name":       "push",
				},
			}
			input := build(jwt, "/deputy.test.v1.TestService/Probe", "github.com/untrusted-org/repo")

			actions, err := engine.EvaluateAll(t.Context(), input, "server", string(ep))
			if err != nil {
				t.Fatalf("EvaluateAll: %v", err)
			}

			for _, action := range actions {
				if ActionTypeIs(action.Type, ActionDeny) {
					return
				}
			}
			t.Errorf("token from an untrusted organization was not denied at %s: the organization allowlist does not reach this entrypoint", ep)
		})
	}
}
