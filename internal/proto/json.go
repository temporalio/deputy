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

// MCPJSONMarshalOptions is the canonical protojson configuration for MCP tool
// results (deputy.mcp.v1): camelCase JSON names — the MCP wire dialect agents
// already consume — compact (the SDK embeds the payload in structuredContent),
// and zero values omitted so results stay small for agent context windows.
// One proto, two documented dialects: the CLI speaks snake_case
// (CLIJSONMarshalOptions), MCP speaks camelCase; both derive from the same
// messages so they can never disagree on content.
func MCPJSONMarshalOptions() protojson.MarshalOptions {
	return protojson.MarshalOptions{
		EmitUnpopulated: false,
		UseProtoNames:   false,
	}
}

// MCPJSONUnmarshalOptions is the canonical protojson configuration for parsing
// MCP tool arguments into deputy.mcp.v1 request messages. Unknown fields are
// rejected (DiscardUnknown: false) as defense in depth behind the generated
// input schemas' additionalProperties: false.
func MCPJSONUnmarshalOptions() protojson.UnmarshalOptions {
	return protojson.UnmarshalOptions{
		DiscardUnknown: false,
	}
}
