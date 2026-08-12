package policy

import "strings"

// Mode selects how a policy's decisions are applied.
type Mode string

// Policy execution modes. Use these typed values instead of raw strings.
const (
	// ModeEnforce applies a policy's decisions as written and is the default
	// when a policy declares no mode.
	ModeEnforce Mode = "enforce"
	// ModeAdvisory downgrades a policy's deny decisions to warnings so a policy
	// can be observed before it blocks anything.
	ModeAdvisory Mode = "advisory"
)

// String returns the mode name.
func (m Mode) String() string { return string(m) }

// Modes returns the canonical execution modes, so surfaces that advertise them
// (completions, validation, docs) derive from this list instead of repeating it.
func Modes() []Mode { return []Mode{ModeEnforce, ModeAdvisory} }

// normalizeMode returns the canonical form of mode, lowercasing and trimming
// whatever an author wrote. The empty mode stays empty and means [ModeEnforce].
func normalizeMode(mode Mode) Mode {
	return Mode(strings.ToLower(strings.TrimSpace(string(mode))))
}

// IsAdvisory reports whether the mode requests advisory evaluation.
func (m Mode) IsAdvisory() bool { return normalizeMode(m) == ModeAdvisory }

// IsValid reports whether the mode is one Deputy knows how to apply. The empty
// mode is valid and means [ModeEnforce].
func (m Mode) IsValid() bool {
	switch normalizeMode(m) {
	case "", ModeEnforce, ModeAdvisory:
		return true
	default:
		return false
	}
}

// Metadata is everything a policy declares about itself apart from its CEL
// program: who it is, and when it should run.
//
// The engine reads Entrypoints, Commands, and Mode; Name and Description are
// carried for reporting surfaces. Ecosystems is recorded for the same reason
// rather than filtering at evaluation time, because the structured loader
// compiles ecosystem scoping into each rule's CEL guard.
//
// The zero Metadata means an unnamed policy with no scoping that runs
// everywhere in enforce mode, which is what a bare CEL body describes.
type Metadata struct {
	Name        string       `json:"name,omitempty"`        // Name identifies the policy.
	Description string       `json:"description,omitempty"` // Description explains the policy's purpose.
	Entrypoints []Entrypoint `json:"entrypoints,omitempty"` // Entrypoints limits the policy to specific evaluation entrypoints.
	Commands    []string     `json:"commands,omitempty"`    // Commands limits the policy to specific CLI commands, in canonical form.
	Ecosystems  []string     `json:"ecosystems,omitempty"`  // Ecosystems records the ecosystems the policy was written for.
	Mode        Mode         `json:"mode,omitempty"`        // Mode selects how decisions are applied; empty means ModeEnforce.
}

// EntrypointNames returns the declared entrypoints as plain strings, for
// surfaces such as proto responses that carry them untyped.
func (m Metadata) EntrypointNames() []string {
	if len(m.Entrypoints) == 0 {
		return nil
	}
	names := make([]string, 0, len(m.Entrypoints))
	for _, ep := range m.Entrypoints {
		names = append(names, ep.String())
	}
	return names
}
