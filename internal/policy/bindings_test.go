package policy

import (
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
)

func TestAllEntrypointsHaveBindings(t *testing.T) {
	for _, ep := range AllEntrypoints {
		if GetBindingProfile(ep) == nil {
			t.Errorf("entrypoint %q has no binding profile", ep)
		}
	}
}

func TestBindingProfilesHaveEntrypoints(t *testing.T) {
	for ep := range BindingProfiles {
		if !ep.IsValid() {
			t.Errorf("binding profile for %q references unknown entrypoint", ep)
		}
	}
}

func TestBindingProfilesHaveDescriptions(t *testing.T) {
	for ep, profile := range BindingProfiles {
		if profile.Description == "" {
			t.Errorf("binding profile for %q has no description", ep)
		}
	}
}

func TestBindingProfilesHaveEnvVar(t *testing.T) {
	for ep, profile := range BindingProfiles {
		vars := profile.Variables()
		if !slices.Contains(vars, "env") {
			t.Errorf("binding profile for %q missing 'env' variable", ep)
		}
	}
}

func TestVariablesForEntrypoint(t *testing.T) {
	tests := []struct {
		entrypoint Entrypoint
		mustHave   []string
	}{
		{
			entrypoint: EntrypointScanVulnerability,
			mustHave:   []string{"vulnerability", "pkg", "env"},
		},
		{
			entrypoint: EntrypointScanReport,
			mustHave:   []string{"vulnerabilities", "packages", "env"},
		},
		{
			entrypoint: EntrypointGoArtifactRequest,
			mustHave:   []string{"request", "env"},
		},
		{
			entrypoint: EntrypointDockerfileReport,
			mustHave:   []string{"dockerfile", "dockerfile_analysis", "env"},
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.entrypoint), func(t *testing.T) {
			vars := VariablesForEntrypoint(tt.entrypoint)
			for _, want := range tt.mustHave {
				if !slices.Contains(vars, want) {
					t.Errorf("entrypoint %q missing expected variable %q", tt.entrypoint, want)
				}
			}
		})
	}
}

func TestRequiredVsOptional(t *testing.T) {
	for ep, profile := range BindingProfiles {
		// Check no overlap between required and optional
		for _, req := range profile.Required {
			if slices.Contains(profile.Optional, req) {
				t.Errorf("entrypoint %q has %q in both required and optional", ep, req)
			}
		}
	}
}

func TestBindingProfileVariables(t *testing.T) {
	profile := BindingProfiles[EntrypointScanVulnerability]
	vars := profile.Variables()

	// Should include both required and optional
	if !slices.Contains(vars, "vulnerability") {
		t.Error("expected 'vulnerability' in variables")
	}
	if !slices.Contains(vars, "env") {
		t.Error("expected 'env' in variables")
	}

	// IsRequired should work
	if !profile.IsRequired("vulnerability") {
		t.Error("expected 'vulnerability' to be required")
	}
	if profile.IsRequired("target") {
		t.Error("expected 'target' to be optional, not required")
	}
}

func TestExampleCategoriesCoverAllEntrypoints(t *testing.T) {
	seen := make(map[Entrypoint]string)
	for _, cat := range ExampleCategories {
		for _, ep := range cat.Entrypoints {
			if ep.Category() != cat.Name {
				t.Errorf("entrypoint %q is in category %q, want %q", ep, cat.Name, ep.Category())
			}
			if prev, ok := seen[ep]; ok {
				t.Errorf("entrypoint %q appears in both %q and %q", ep, prev, cat.Name)
			}
			seen[ep] = cat.Name
		}
	}

	for _, ep := range AllEntrypoints {
		if _, ok := seen[ep]; !ok {
			t.Errorf("entrypoint %q missing from ExampleCategories", ep)
		}
	}
}

// undeclaredBindingVars lists variables that a BindingProfile advertises but
// the CEL environment never declares, so any policy using them fails to
// compile with "undeclared reference".
//
// These are real defects, tracked in #129, not exemptions. The list exists so
// the gap is enforced at its current size instead of growing quietly. Every
// entry is a promise the docs make and the engine cannot keep: sandbox_network
// is entirely unusable, sandbox_command still lacks an evaluation site, and
// `licenses` is advertised at four proxy entrypoints nothing binds.
//
// A subtlety this list cannot see: declarations are global to every CEL env,
// not per entrypoint. sandbox_command's profile lists `command`, which now
// passes these tests only because sandbox_execution's caller declares the
// name; nothing binds it at sandbox_command, so a policy scoped there still
// fails at eval time. Per-entrypoint environments (#127) are the real fix;
// until then, treat "declared" as necessary but not sufficient.
//
// TestBindingProfilesDeclareRealVariables fails both when a new name appears
// here and when a listed name starts working, so fixing one requires deleting
// its line and the list cannot rot.
// Every survivor here has no code that binds it, so declaring it would trade
// "undeclared reference" at compile time for "no such attribute" at eval time,
// which is a worse trade: the policy would look valid and fail during a scan.
// Each needs an evaluation site before it can be declared.
var undeclaredBindingVars = map[string]string{
	"host":           "#129 sandbox_network has no evaluation site",
	"licenses":       "#129 no *_artifact_request caller binds it",
	"port":           "#129 sandbox_network has no evaluation site",
	"protocol":       "#129 sandbox_network has no evaluation site",
	"sandbox_config": "#129 sandbox_network and sandbox_command have no evaluation site",
	"source":         "#129 sandbox_execution binds no source",
}

// TestBindingProfilesDeclareRealVariables pins the contract that
// internal/policy/bindings.go claims to be "the authoritative source for what's
// available where": a variable an entrypoint advertises must actually be
// declared in the CEL environment.
//
// Nothing enforced this before, so the two lists drifted and the docs generated
// from BindingProfiles told authors to use variables that cannot compile.
func TestBindingProfilesDeclareRealVariables(t *testing.T) {
	t.Parallel()
	declared := DefaultVariableNames()

	missing := map[string][]string{}
	for ep, profile := range BindingProfiles {
		for _, name := range profile.Variables() {
			if !slices.Contains(declared, name) {
				missing[name] = append(missing[name], string(ep))
			}
		}
	}

	for name, entrypoints := range missing {
		if _, known := undeclaredBindingVars[name]; !known {
			slices.Sort(entrypoints)
			t.Errorf("binding profiles advertise %q at %v but the CEL env does not declare it; "+
				"add it to DefaultVariableNames or remove it from the profile",
				name, entrypoints)
		}
	}

	// The other direction: a known gap that has been closed must leave the list,
	// otherwise it stops describing reality and starts hiding regressions.
	for name, ref := range undeclaredBindingVars {
		if _, still := missing[name]; !still {
			t.Errorf("%q is declared now (%s); delete it from undeclaredBindingVars", name, ref)
		}
	}
}

// TestRequiredVariablesAreDeclared is the sharper half of the same contract.
// "Required" tells authors in bindings.go that they "can rely on these without
// null checks", so a Required variable that is not even declared is the worst
// case: the documentation is actively wrong rather than merely incomplete.
func TestRequiredVariablesAreDeclared(t *testing.T) {
	t.Parallel()
	declared := DefaultVariableNames()
	for ep, profile := range BindingProfiles {
		for _, name := range profile.Required {
			if slices.Contains(declared, name) {
				continue
			}
			if _, known := undeclaredBindingVars[name]; known {
				continue
			}
			t.Errorf("entrypoint %q requires %q, which the CEL env does not declare", ep, name)
		}
	}
}

// serviceEntrypointInputs pairs each service authorization entrypoint with the
// proto message the server actually evaluates at it. The payload is the ground
// truth for what a policy can reference, because ProtoToMap keys the CEL
// activation by the message's field names, so this is what the binding profile
// has to agree with.
var serviceEntrypointInputs = map[Entrypoint]proto.Message{
	EntrypointServiceScanRequest:    &policyv1.ServiceScanRequestPolicyInput{},
	EntrypointServiceListRequest:    &policyv1.ServiceListRequestPolicyInput{},
	EntrypointServiceSBOMRequest:    &policyv1.ServiceSbomRequestPolicyInput{},
	EntrypointServiceDiffRequest:    &policyv1.ServiceDiffRequestPolicyInput{},
	EntrypointServiceSecretsRequest: &policyv1.ServiceSecretsRequestPolicyInput{},
	EntrypointServiceGraphRequest:   &policyv1.ServiceGraphRequestPolicyInput{},
}

// messageFieldNames returns a message's field names in proto (snake_case) form,
// which is the form ProtoToMap uses for CEL activation keys.
func messageFieldNames(msg proto.Message) []string {
	fields := msg.ProtoReflect().Descriptor().Fields()
	names := make([]string, 0, fields.Len())
	for i := range fields.Len() {
		names = append(names, string(fields.Get(i).Name()))
	}
	slices.Sort(names)
	return names
}

// TestServiceEntrypointBindingsMatchTheirPayloads derives the expected variable
// set for each service entrypoint from its payload message instead of trusting
// the hand-written binding profile, because the two drifted: the
// service_diff_request profile advertised "target", which its payload has never
// carried, while the diff_base and diff_target the payload does carry were
// undeclared and so could not compile. The entrypoint's whole purpose is to
// authorize a request against its target, and neither side was reachable.
//
// Both directions matter. A variable the profile advertises but the payload
// omits is a documented control that silently has no value. A payload field the
// profile omits cannot be referenced at all, which fails the request closed at
// compile time and makes the field dead.
func TestServiceEntrypointBindingsMatchTheirPayloads(t *testing.T) {
	t.Parallel()

	// Every service entrypoint must appear above, otherwise a new one could
	// ship with a drifted profile and nothing would compare it to anything.
	for _, ep := range EntrypointsService {
		if _, ok := serviceEntrypointInputs[ep]; !ok {
			t.Errorf("service entrypoint %q has no payload in serviceEntrypointInputs, so its binding profile is unchecked", ep)
		}
	}

	for ep, msg := range serviceEntrypointInputs {
		t.Run(string(ep), func(t *testing.T) {
			profile := GetBindingProfile(ep)
			if profile == nil {
				t.Fatalf("entrypoint %q has no binding profile", ep)
			}

			want := messageFieldNames(msg)
			if len(want) == 0 {
				t.Fatalf("payload %T declares no fields; the comparison would be vacuous", msg)
			}
			got := profile.Variables()
			slices.Sort(got)

			for _, name := range got {
				if !slices.Contains(want, name) {
					t.Errorf("binding profile advertises %q, which %T does not carry, so a policy using it has nothing to match on", name, msg)
				}
			}
			for _, name := range want {
				if !slices.Contains(got, name) {
					t.Errorf("%T carries %q, which the binding profile omits, so a policy referencing it cannot compile", msg, name)
				}
			}
		})
	}
}

// TestDiffProfilesMatchTheirInputMessages tests that a variable a diff binding
// profile advertises is declared by the proto message that documents the same
// entrypoint.
//
// The two contracts diverged in both directions on this branch. The report
// message declared two Target fields no caller populated, and both diff
// profiles advertised the refs while neither message declared them, so
// schema-driven tooling and CEL disagreed about the same entrypoint. Deriving
// the profile from the descriptor is the end state and needs an import cycle
// resolved first, so until then this test keeps the two hand-written lists in
// agreement.
func TestDiffProfilesMatchTheirInputMessages(t *testing.T) {
	tests := []struct {
		entrypoint Entrypoint
		message    proto.Message
	}{
		{EntrypointDiffReport, &policyv1.DiffReportPolicyInput{}},
		{EntrypointDiffVulnerability, &policyv1.DiffVulnerabilityPolicyInput{}},
		{EntrypointDiffDependencyChange, &policyv1.DiffDependencyChangePolicyInput{}},
	}

	for _, tt := range tests {
		t.Run(string(tt.entrypoint), func(t *testing.T) {
			declared := map[string]bool{}
			fields := tt.message.ProtoReflect().Descriptor().Fields()
			for i := range fields.Len() {
				declared[string(fields.Get(i).Name())] = true
			}

			profile := GetBindingProfile(tt.entrypoint)
			for _, name := range append(append([]string{}, profile.Required...), profile.Optional...) {
				// pkg and dependency are aliases the payload adds for
				// consistency with scan and fix entrypoints, so they have no
				// field of their own.
				if name == "pkg" || name == "dependency" {
					continue
				}
				if !declared[name] {
					t.Errorf("profile advertises %q, which %s does not declare: a policy derived from the proto sees a different surface than CEL binds",
						name, tt.message.ProtoReflect().Descriptor().FullName())
				}
			}
		})
	}
}
