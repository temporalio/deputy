package policy

import (
	"fmt"
	"strings"
)

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
// The engine reads Entrypoints, Commands, and Mode. Name, Description, and
// Ecosystems are carried for reporting and do not filter anything.
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

// validate reports whether everything the policy declares about itself is
// something Deputy can apply.
//
// Every route into the engine shares this check, because only one of them passes
// through the authoring loader: a compiled bundle is JSON, so unmarshalling it
// fills a Metadata with whatever the file says. Left unchecked, both mistakes an
// operator can make in that file fail open. A command the engine does not
// recognize is dropped from the filter set it builds, so a policy that asked for
// one command runs for every command; and a mode that is not exactly advisory is
// enforced, so denials the author wanted merely observed block instead.
//
// A declaration that names nothing is rejected for the same reason rather than
// skipped: the engine filters only on a non-empty set, so an all-blank list of
// commands or entrypoints would widen the policy to everywhere.
func (m Metadata) validate() error {
	for _, ep := range m.Entrypoints {
		if !IsAllowedEntrypoint(trimmedEntrypoint(ep)) {
			return fmt.Errorf("invalid entrypoint %q (not in allowed set)", ep)
		}
	}
	for _, cmd := range m.Commands {
		if !IsAllowedCommand(cmd) {
			return fmt.Errorf("invalid command %q (not in allowed set)", cmd)
		}
	}
	if !m.Mode.IsValid() {
		return fmt.Errorf("invalid mode %q (expected %s)", m.Mode, modeVocabulary())
	}
	return nil
}

// modeVocabulary renders the canonical modes for an error message, derived from
// [Modes] so no message can name a vocabulary that has moved on.
func modeVocabulary() string {
	names := make([]string, 0, len(Modes()))
	for _, mode := range Modes() {
		names = append(names, mode.String())
	}
	return strings.Join(names, "|")
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
