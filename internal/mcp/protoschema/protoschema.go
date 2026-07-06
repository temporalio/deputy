// Package protoschema derives MCP tool JSON Schemas from protobuf message
// descriptors, so a tool's advertised contract is generated from the proto
// source of truth (deputy.mcp.v1) instead of hand-maintained literals that
// drift.
//
// The output deliberately targets what MCP clients accept, which is narrower
// than JSON Schema (see the mcp-schema constraints learned in production):
//
//   - no $ref and no oneOf/anyOf/allOf anywhere: nested messages are inlined,
//     and messages containing proto oneofs are rejected;
//   - enum-like values appear as string enums: proto enum fields use the
//     declared value names, and string fields constrained with
//     (buf.validate.field).string.in use that list, the same list
//     protovalidate enforces server-side, so the advertised schema can never
//     promise more than the server accepts;
//   - int64/uint64 map to JSON strings (the protojson wire form); prefer int32
//     in mcp.v1 messages so agents see JSON numbers;
//   - field descriptions come from the .proto leading comments via the
//     embedded descriptor set, making the proto comment the single authored
//     description for schema, docs, and hover surfaces.
package protoschema

import (
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	validate "buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"github.com/temporalio/deputy/internal/proto/descriptorset"
)

// Options configures schema generation.
type Options struct {
	// Input marks a request schema: unknown properties are rejected
	// (additionalProperties: false) and fields with (buf.validate.field).required
	// become required. Result schemas stay permissive so additive server fields
	// never fail the SDK's output validation on older schemas.
	Input bool
}

// ForMessage derives an MCP-safe JSON Schema for the given message descriptor.
// It fails loudly on shapes MCP clients cannot express (proto oneof, recursive
// messages, google.protobuf.Any/Struct) rather than emitting a schema that a
// client would reject or that would misdescribe the wire.
func ForMessage(md protoreflect.MessageDescriptor, opts Options) (*jsonschema.Schema, error) {
	return messageSchema(md, opts, make(map[protoreflect.FullName]bool))
}

func messageSchema(md protoreflect.MessageDescriptor, opts Options, visiting map[protoreflect.FullName]bool) (*jsonschema.Schema, error) {
	if visiting[md.FullName()] {
		return nil, fmt.Errorf("recursive message %s cannot be expressed without $ref", md.FullName())
	}
	visiting[md.FullName()] = true
	defer delete(visiting, md.FullName())

	if md.Oneofs().Len() > 0 && realOneofCount(md) > 0 {
		return nil, fmt.Errorf("message %s uses a proto oneof; MCP clients reject oneOf/anyOf schemas; model alternatives as optional fields validated by the handler", md.FullName())
	}

	schema := &jsonschema.Schema{
		Type:       "object",
		Properties: map[string]*jsonschema.Schema{},
	}
	if desc := descriptorset.Comment(md.FullName()); desc != "" {
		schema.Description = desc
	}
	if opts.Input {
		schema.AdditionalProperties = &jsonschema.Schema{Not: &jsonschema.Schema{}}
	}

	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		fs, err := fieldSchema(fd, opts, visiting)
		if err != nil {
			return nil, err
		}
		// The field's own comment wins over any description inherited from the
		// field's type (e.g. an enum's comment): the field comment is the
		// contextual contract.
		if desc := descriptorset.Comment(fd.FullName()); desc != "" {
			fs.Description = desc
		}
		schema.Properties[fd.JSONName()] = fs
		if opts.Input && fieldRules(fd).GetRequired() {
			schema.Required = append(schema.Required, fd.JSONName())
		}
	}
	return schema, nil
}

// realOneofCount counts non-synthetic oneofs (proto3 optional fields create
// synthetic oneofs that are fine on the wire).
func realOneofCount(md protoreflect.MessageDescriptor) int {
	n := 0
	for i := 0; i < md.Oneofs().Len(); i++ {
		if !md.Oneofs().Get(i).IsSynthetic() {
			n++
		}
	}
	return n
}

func fieldSchema(fd protoreflect.FieldDescriptor, opts Options, visiting map[protoreflect.FullName]bool) (*jsonschema.Schema, error) {
	if fd.IsMap() {
		// Map value constraints live under map.values in buf.validate.
		valueSchema, err := scalarOrMessageSchema(fd.MapValue(), fieldRules(fd).GetMap().GetValues(), opts, visiting)
		if err != nil {
			return nil, fmt.Errorf("map field %s: %w", fd.FullName(), err)
		}
		return &jsonschema.Schema{Type: "object", AdditionalProperties: valueSchema}, nil
	}
	if fd.IsList() {
		// Per-item constraints live under repeated.items in buf.validate.
		repeated := fieldRules(fd).GetRepeated()
		item, err := scalarOrMessageSchema(fd, repeated.GetItems(), opts, visiting)
		if err != nil {
			return nil, fmt.Errorf("repeated field %s: %w", fd.FullName(), err)
		}
		s := &jsonschema.Schema{Type: "array", Items: item}
		if min := repeated.GetMinItems(); min > 0 {
			s.MinItems = jsonschema.Ptr(int(min))
		}
		return s, nil
	}
	return scalarOrMessageSchema(fd, fieldRules(fd), opts, visiting)
}

func scalarOrMessageSchema(fd protoreflect.FieldDescriptor, rules *validate.FieldRules, opts Options, visiting map[protoreflect.FullName]bool) (*jsonschema.Schema, error) {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return stringSchema(rules.GetString()), nil
	case protoreflect.BoolKind:
		return &jsonschema.Schema{Type: "boolean"}, nil
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
		protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return &jsonschema.Schema{Type: "integer"}, nil
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind,
		protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		// protojson serializes 64-bit integers as JSON strings; describe the
		// wire truthfully. Prefer int32 in mcp.v1 messages.
		return &jsonschema.Schema{Type: "string"}, nil
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return &jsonschema.Schema{Type: "number"}, nil
	case protoreflect.BytesKind:
		// protojson serializes bytes as base64 strings.
		return &jsonschema.Schema{Type: "string"}, nil
	case protoreflect.EnumKind:
		return enumSchema(fd.Enum()), nil
	case protoreflect.MessageKind:
		return wellKnownOrNested(fd.Message(), opts, visiting)
	default:
		return nil, fmt.Errorf("field %s: unsupported kind %s", fd.FullName(), fd.Kind())
	}
}

// stringSchema maps buf.validate string rules onto the schema: in → enum,
// min_len → minLength, pattern → pattern. The rules are the same ones
// protovalidate enforces, so schema and server can't disagree. Callers pass
// the rules from the right buf.validate location (the field itself,
// repeated.items, or map.values).
func stringSchema(rules *validate.StringRules) *jsonschema.Schema {
	s := &jsonschema.Schema{Type: "string"}
	if rules == nil {
		return s
	}
	if in := rules.GetIn(); len(in) > 0 {
		s.Enum = make([]any, 0, len(in))
		for _, v := range in {
			s.Enum = append(s.Enum, v)
		}
	}
	if min := rules.GetMinLen(); min > 0 {
		s.MinLength = jsonschema.Ptr(int(min))
	}
	if p := rules.GetPattern(); p != "" {
		s.Pattern = p
	}
	return s
}

// enumSchema renders a proto enum field as a string enum of the declared value
// names, exactly what protojson emits on the wire.
func enumSchema(ed protoreflect.EnumDescriptor) *jsonschema.Schema {
	values := ed.Values()
	s := &jsonschema.Schema{Type: "string", Enum: make([]any, 0, values.Len())}
	for i := 0; i < values.Len(); i++ {
		s.Enum = append(s.Enum, string(values.Get(i).Name()))
	}
	if desc := descriptorset.Comment(ed.FullName()); desc != "" {
		s.Description = desc
	}
	return s
}

func wellKnownOrNested(md protoreflect.MessageDescriptor, opts Options, visiting map[protoreflect.FullName]bool) (*jsonschema.Schema, error) {
	switch md.FullName() {
	case "google.protobuf.Timestamp":
		return &jsonschema.Schema{Type: "string", Description: "RFC 3339 timestamp"}, nil
	case "google.protobuf.Duration":
		return &jsonschema.Schema{Type: "string", Description: "duration, e.g. \"3.5s\""}, nil
	case "google.protobuf.Any", "google.protobuf.Struct", "google.protobuf.Value":
		return nil, fmt.Errorf("message %s cannot be described as a flat schema; avoid it in mcp.v1", md.FullName())
	}
	return messageSchema(md, opts, visiting)
}

// fieldRules returns the buf.validate rules for a field, or an empty rules
// message when none are declared.
func fieldRules(fd protoreflect.FieldDescriptor) *validate.FieldRules {
	opts := fd.Options()
	if opts == nil || !proto.HasExtension(opts, validate.E_Field) {
		return &validate.FieldRules{}
	}
	rules, ok := proto.GetExtension(opts, validate.E_Field).(*validate.FieldRules)
	if !ok || rules == nil {
		return &validate.FieldRules{}
	}
	return rules
}
