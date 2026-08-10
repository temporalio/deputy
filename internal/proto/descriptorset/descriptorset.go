// Package descriptorset embeds Deputy's compiled proto descriptors with source
// info, so tooling can read the comments written in the .proto files at
// runtime, because the generated Go descriptors strip SourceCodeInfo. This makes the
// proto comments the single authored source for human- and agent-facing
// descriptions: MCP tool schemas derive field descriptions from it today, and
// docs generation can reuse it.
//
// Regenerate descriptorset.binpb whenever protos change, alongside buf generate:
//
//	cd api && buf build --exclude-imports -o ../internal/proto/descriptorset/descriptorset.binpb
package descriptorset

import (
	_ "embed"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

//go:embed descriptorset.binpb
var raw []byte

// parse decodes the embedded descriptor set once, shared by every index built
// from it.
var parse = sync.OnceValues(func() (*descriptorpb.FileDescriptorSet, error) {
	var fds descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(raw, &fds); err != nil {
		return nil, fmt.Errorf("parse embedded descriptor set: %w", err)
	}
	return &fds, nil
})

// resolved holds the embedded set as protoreflect descriptors. The set is built
// with --exclude-imports, so references to well-known types cannot be resolved
// and become placeholders; that is fine for structural queries over Deputy's
// own messages and is why unresolvable references are allowed.
var resolved = sync.OnceValues(func() (*protoregistry.Files, error) {
	fds, err := parse()
	if err != nil {
		return nil, err
	}
	files, err := (protodesc.FileOptions{AllowUnresolvable: true}).NewFiles(fds)
	if err != nil {
		return nil, fmt.Errorf("resolve embedded descriptor set: %w", err)
	}
	return files, nil
})

// RangeMessages calls fn for every message declared in Deputy's protos,
// including nested messages but not the synthetic map-entry messages. It stops
// early when fn returns false. Callers get the complete schema, not just the
// parts linked into the current binary, so schema-derived checks cannot go
// blind on a package nobody imported.
func RangeMessages(fn func(protoreflect.MessageDescriptor) bool) error {
	files, err := resolved()
	if err != nil {
		return err
	}
	var walk func(protoreflect.MessageDescriptors) bool
	walk = func(msgs protoreflect.MessageDescriptors) bool {
		for i := range msgs.Len() {
			md := msgs.Get(i)
			if md.IsMapEntry() {
				continue
			}
			if !fn(md) || !walk(md.Messages()) {
				return false
			}
		}
		return true
	}
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		return walk(fd.Messages())
	})
	return nil
}

// comment index keyed by the element's proto full name (messages, fields,
// enums, enum values), holding the cleaned leading comment.
var load = sync.OnceValues(func() (_ map[protoreflect.FullName]string, retErr error) {
	// Indexing walks source-info paths with direct slice indexing; a
	// malformed or tampered descriptor set must degrade to "no comments",
	// not crash the process.
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("index embedded descriptor set: %v", r)
		}
	}()
	fds, err := parse()
	if err != nil {
		return nil, err
	}
	idx := make(map[protoreflect.FullName]string)
	for _, fd := range fds.GetFile() {
		indexFile(idx, fd)
	}
	return idx, nil
})

// scalarMapFields indexes the field names declared anywhere in Deputy's protos
// as a map with scalar values (map<string, string>, map<string, int32>, ...).
// Map fields with message values are excluded: those are structured data the
// schema describes, not opaque key/value pairs.
var scalarMapFields = sync.OnceValues(func() (map[string]struct{}, error) {
	fds, err := parse()
	if err != nil {
		return nil, err
	}
	names := make(map[string]struct{})
	for _, fd := range fds.GetFile() {
		for _, msg := range fd.GetMessageType() {
			collectScalarMapFields(names, msg)
		}
	}
	return names, nil
})

// ScalarMapFieldNames returns the sorted names of every field in Deputy's
// protos declared as a map with scalar values. The names come from the embedded
// descriptor set, so callers that need to treat opaque key/value maps
// differently from schema-described structures do not have to maintain their
// own list. It returns nil when the descriptor set cannot be read.
func ScalarMapFieldNames() []string {
	names, err := scalarMapFields()
	if err != nil {
		return nil
	}
	return slices.Sorted(maps.Keys(names))
}

// IsScalarMapField reports whether name is declared anywhere in Deputy's protos
// as a map field with scalar values.
func IsScalarMapField(name string) bool {
	names, err := scalarMapFields()
	if err != nil {
		return false
	}
	_, ok := names[name]
	return ok
}

// collectScalarMapFields records the scalar-valued map fields of a message and
// of every message nested inside it. A map field is a repeated message field
// whose element type is the synthetic map-entry message the compiler generates
// next to it, so the entry's value field says what the map holds.
func collectScalarMapFields(names map[string]struct{}, msg *descriptorpb.DescriptorProto) {
	entries := make(map[string]*descriptorpb.DescriptorProto, len(msg.GetNestedType()))
	for _, nested := range msg.GetNestedType() {
		if nested.GetOptions().GetMapEntry() {
			entries[nested.GetName()] = nested
		}
	}
	for _, field := range msg.GetField() {
		if field.GetLabel() != descriptorpb.FieldDescriptorProto_LABEL_REPEATED || field.GetType() != descriptorpb.FieldDescriptorProto_TYPE_MESSAGE {
			continue
		}
		typeName := field.GetTypeName()
		entry, ok := entries[typeName[strings.LastIndex(typeName, ".")+1:]]
		if !ok {
			continue
		}
		for _, entryField := range entry.GetField() {
			if entryField.GetName() == "value" && entryField.GetType() != descriptorpb.FieldDescriptorProto_TYPE_MESSAGE {
				names[field.GetName()] = struct{}{}
			}
		}
	}
	for _, nested := range msg.GetNestedType() {
		if !nested.GetOptions().GetMapEntry() {
			collectScalarMapFields(names, nested)
		}
	}
}

// Comment returns the cleaned leading comment for the proto element with the
// given full name (message, field, enum, or enum value), or "" when the
// element has no comment or the descriptor set is unavailable.
func Comment(name protoreflect.FullName) string {
	idx, err := load()
	if err != nil {
		return ""
	}
	return idx[name]
}

// Summary returns the first sentence of the proto element's leading comment,
// for surfaces that need a one-line description (doc tables, completion hints)
// rather than the full authored paragraph. The trailing period is kept, since
// it is part of the sentence the proto author wrote.
func Summary(name protoreflect.FullName) string {
	return firstSentence(Comment(name))
}

// firstSentence trims a comment to its first sentence. A period only ends the
// sentence when an uppercase letter follows, so abbreviations, URLs, and
// version strings mid-sentence do not truncate it.
func firstSentence(comment string) string {
	comment = strings.TrimSpace(comment)
	if comment == "" {
		return ""
	}
	line := strings.ReplaceAll(comment, "\n", " ")
	for idx := 0; ; {
		next := strings.Index(line[idx:], ". ")
		if next == -1 {
			return line
		}
		idx += next
		rest := strings.TrimLeft(line[idx+1:], " ")
		if rest != "" {
			if r := rune(rest[0]); r >= 'A' && r <= 'Z' {
				return line[:idx+1]
			}
		}
		idx += 2
	}
}

// indexFile walks a file's source-code-info locations and records leading
// comments for messages (path [4 m]), fields ([4 m 2 f]), enums ([5 e]), and
// enum values ([5 e 2 v]), including nested messages.
func indexFile(idx map[protoreflect.FullName]string, fd *descriptorpb.FileDescriptorProto) {
	sci := fd.GetSourceCodeInfo()
	if sci == nil {
		return
	}
	pkg := protoreflect.FullName(fd.GetPackage())
	for _, loc := range sci.GetLocation() {
		comment := cleanComment(loc.GetLeadingComments())
		if comment == "" {
			continue
		}
		if name, ok := elementName(pkg, fd, loc.GetPath()); ok {
			idx[name] = comment
		}
	}
}

// elementName resolves a source-code-info path to the element's full name.
// Supported paths: top-level and nested messages and their fields, top-level
// enums and their values. Other paths (services, extensions, options) return
// ok=false; extend as tooling needs them.
func elementName(pkg protoreflect.FullName, fd *descriptorpb.FileDescriptorProto, path []int32) (protoreflect.FullName, bool) {
	const (
		fileMessages = 4 // FileDescriptorProto.message_type
		fileEnums    = 5 // FileDescriptorProto.enum_type
		msgFields    = 2 // DescriptorProto.field
		msgNested    = 3 // DescriptorProto.nested_type
		msgEnums     = 4 // DescriptorProto.enum_type
		enumValues   = 2 // EnumDescriptorProto.value
	)
	if len(path) < 2 {
		return "", false
	}
	switch path[0] {
	case fileMessages:
		msg := fd.GetMessageType()[path[1]]
		name := pkg.Append(protoreflect.Name(msg.GetName()))
		rest := path[2:]
		for len(rest) > 0 {
			if len(rest) == 2 && rest[0] == msgFields {
				f := msg.GetField()[rest[1]]
				return name.Append(protoreflect.Name(f.GetName())), true
			}
			if len(rest) >= 2 && rest[0] == msgNested {
				msg = msg.GetNestedType()[rest[1]]
				name = name.Append(protoreflect.Name(msg.GetName()))
				rest = rest[2:]
				continue
			}
			if len(rest) >= 2 && rest[0] == msgEnums {
				e := msg.GetEnumType()[rest[1]]
				name = name.Append(protoreflect.Name(e.GetName()))
				if len(rest) == 4 && rest[2] == enumValues {
					v := e.GetValue()[rest[3]]
					return name.Append(protoreflect.Name(v.GetName())), true
				}
				if len(rest) == 2 {
					return name, true
				}
				return "", false
			}
			return "", false
		}
		return name, true
	case fileEnums:
		e := fd.GetEnumType()[path[1]]
		name := pkg.Append(protoreflect.Name(e.GetName()))
		if len(path) == 2 {
			return name, true
		}
		if len(path) == 4 && path[2] == enumValues {
			v := e.GetValue()[path[3]]
			return name.Append(protoreflect.Name(v.GetName())), true
		}
		return "", false
	default:
		return "", false
	}
}

// cleanComment normalizes a leading comment: strips the per-line "//" padding
// artifacts, joins wrapped lines, and trims whitespace, yielding prose suitable
// for a schema description.
func cleanComment(c string) string {
	lines := strings.Split(c, "\n")
	parts := make([]string, 0, len(lines))
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return strings.Join(parts, " ")
}
