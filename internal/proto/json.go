package proto

import "google.golang.org/protobuf/encoding/protojson"

// CLIJSONMarshalOptions is the canonical protojson configuration for Deputy's
// machine-readable output (--format json and agent prompts): proto field names
// (snake_case — the documented CLI JSON contract, congruent with CEL policy
// inputs), two-space multiline indentation, and zero values omitted. Every
// proto-marshaling output path should use this so all commands emit the same
// JSON dialect; deliberate deviations (e.g. policy inputs emit zero values so
// CEL size() works on empty lists) stay local with a comment explaining why.
func CLIJSONMarshalOptions() protojson.MarshalOptions {
	return protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}
}
