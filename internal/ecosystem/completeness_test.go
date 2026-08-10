package ecosystem

import (
	"slices"
	"testing"
)

// TestRegistrationsCarryEveryProjection pins the completeness half of the
// registry contract: every registered ecosystem supplies every projection, and
// the only way to leave one blank is to declare it absent. Adding a projection
// to RequiredProjections, or an ecosystem that forgets one, fails here instead
// of silently producing an empty string somewhere downstream.
func TestRegistrationsCarryEveryProjection(t *testing.T) {
	for _, reg := range Default().All() {
		for _, projection := range RequiredProjections() {
			t.Run(string(reg.Ecosystem)+"/"+string(projection), func(t *testing.T) {
				value, ok := reg.Projection(projection)
				if !ok {
					t.Fatalf("Registration.Projection(%q) is not implemented", projection)
				}
				empty := isEmptyProjection(value)
				switch {
				case reg.Lacks(projection) && !empty:
					t.Errorf("%s declares %s absent but supplies %v", reg.Ecosystem, projection, value)
				case !reg.Lacks(projection) && empty:
					t.Errorf("%s is missing %s; supply it or declare it absent", reg.Ecosystem, projection)
				}
			})
		}
	}
}

// TestRegistrationTokensAreCanonical pins that a registration's own identifier
// is a canonical token, so the registry cannot introduce a spelling that
// policies and tools would fail to resolve.
func TestRegistrationTokensAreCanonical(t *testing.T) {
	for _, reg := range Default().All() {
		t.Run(string(reg.Ecosystem), func(t *testing.T) {
			token, known := Canonical(string(reg.Ecosystem))
			if !known || token != string(reg.Ecosystem) {
				t.Errorf("Canonical(%q) = (%q, %t), want (%q, true)", reg.Ecosystem, token, known, reg.Ecosystem)
			}
			if !slices.Contains(CanonicalEcosystems(), string(reg.Ecosystem)) {
				t.Errorf("CanonicalEcosystems() does not include registered %q", reg.Ecosystem)
			}
		})
	}
}

// TestEveryProjectionResolvesBack is the invariant that would have caught the
// original defect: every name Deputy renders for an ecosystem, from any
// projection, resolves back to that ecosystem's canonical token. A display name
// or OSV name the resolver does not recognize means a surface can emit a
// spelling that nothing else understands, which is exactly how "GitHub Actions"
// escaped into policy inputs.
func TestEveryProjectionResolvesBack(t *testing.T) {
	type projected struct {
		eco    Ecosystem
		source string
		value  string
	}

	var cases []projected
	for _, reg := range Default().All() {
		cases = append(cases,
			projected{reg.Ecosystem, "display_name", reg.DisplayName},
			projected{reg.Ecosystem, "display", Display(reg.Ecosystem)},
		)
		if !reg.Lacks(ProjectionOSVName) {
			cases = append(cases, projected{reg.Ecosystem, "osv_name", reg.OSVName})
		}
		for _, alias := range reg.Aliases {
			cases = append(cases, projected{reg.Ecosystem, "alias", alias})
		}
	}
	for _, reg := range extraCanonicalEcosystems {
		cases = append(cases,
			projected{reg.Ecosystem, "extra_display_name", reg.DisplayName},
			projected{reg.Ecosystem, "extra_display", Display(reg.Ecosystem)},
		)
		for _, alias := range reg.Aliases {
			cases = append(cases, projected{reg.Ecosystem, "extra_alias", alias})
		}
	}

	for _, tc := range cases {
		t.Run(string(tc.eco)+"/"+tc.source+"/"+tc.value, func(t *testing.T) {
			token, known := Canonical(tc.value)
			if !known {
				t.Fatalf("Canonical(%q) does not recognize the %s of %s", tc.value, tc.source, tc.eco)
			}
			if token != string(tc.eco) {
				t.Errorf("Canonical(%q) = %q, want %q", tc.value, token, tc.eco)
			}
		})
	}
}

// TestDisplayIsDefinedForEveryToken pins that Display covers the whole canonical
// vocabulary, so no caller needs a local table of human-readable names.
func TestDisplayIsDefinedForEveryToken(t *testing.T) {
	for _, token := range CanonicalEcosystems() {
		t.Run(token, func(t *testing.T) {
			display := Display(Ecosystem(token))
			if display == "" {
				t.Fatalf("Display(%q) is empty", token)
			}
			if back := CanonicalOrRaw(display); back != token {
				t.Errorf("Display(%q) = %q, which resolves back to %q", token, display, back)
			}
		})
	}
}

// TestPURLTypeIsDefinedForEveryToken pins that [PURLType] covers the whole
// canonical vocabulary, including the registry-less tokens, so no caller needs
// a local ecosystem-to-purl-type switch. The registered half is enforced by
// [TestRegistrationsCarryEveryProjection]; this covers the extras, which is the
// half that shipped ConanCenter with no purl type at all.
func TestPURLTypeIsDefinedForEveryToken(t *testing.T) {
	for _, token := range CanonicalEcosystems() {
		t.Run(token, func(t *testing.T) {
			if PURLType(Ecosystem(token)) == "" {
				t.Errorf("PURLType(%q) is empty", token)
			}
		})
	}
}

// isEmptyProjection reports whether a projection value counts as unsupplied.
func isEmptyProjection(value any) bool {
	switch v := value.(type) {
	case string:
		return v == ""
	case []string:
		return len(v) == 0
	case Capability:
		return v == 0
	default:
		return value == nil
	}
}
