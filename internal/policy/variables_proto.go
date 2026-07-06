package policy

import (
	"maps"
	"slices"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	graphv1 "github.com/temporalio/deputy/gen/deputy/graph/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

// variableMessageTypes maps the proto type names used in variable metadata
// (see variableMetadataByName) to their message descriptors, so tooling — LSP
// completions today, docs generation tomorrow — derives field lists from the
// proto source of truth instead of hand-maintained copies that drift.
var variableMessageTypes = map[string]protoreflect.MessageDescriptor{
	"dependencyv1.Package":    (&dependencyv1.Package{}).ProtoReflect().Descriptor(),
	"vulnerabilityv1.Finding": (&vulnerabilityv1.Finding{}).ProtoReflect().Descriptor(),
	"graphv1.Node":            (&graphv1.Node{}).ProtoReflect().Descriptor(),
	"graphv1.Edge":            (&graphv1.Edge{}).ProtoReflect().Descriptor(),
	"targetv1.Target":         (&targetv1.Target{}).ProtoReflect().Descriptor(),
	"policyv1.JWTClaims":      (&policyv1.JWTClaims{}).ProtoReflect().Descriptor(),
	"policyv1.Environment":    (&policyv1.Environment{}).ProtoReflect().Descriptor(),
}

// ProtoVariableTypeNames returns the proto-backed variable type names used in
// variable metadata (e.g. "vulnerabilityv1.Finding"), sorted, so tooling can
// enumerate the types whose fields derive from proto descriptors.
func ProtoVariableTypeNames() []string {
	return slices.Sorted(maps.Keys(variableMessageTypes))
}

// VariableMessageDescriptor resolves a proto-backed variable type name to its
// message descriptor. ok is false for non-proto types such as "object".
func VariableMessageDescriptor(typeName string) (protoreflect.MessageDescriptor, bool) {
	md, ok := variableMessageTypes[typeName]
	return md, ok
}

// VariableFieldCompletions returns the CEL field names (proto field names,
// snake_case) available under a dotted variable path such as "pkg" or
// "target.provenance", resolved by walking proto descriptors from the
// variable's declared type. For list-typed variables it completes the element
// type, matching how CEL comprehension variables and indexing expose elements.
// ok is false when the path does not resolve to a proto message — for example
// object-typed variables — letting callers fall back to hand-maintained lists.
func VariableFieldCompletions(path string) (fields []string, ok bool) {
	parts := strings.Split(strings.TrimSpace(path), ".")
	if len(parts) == 0 || parts[0] == "" {
		return nil, false
	}

	meta, found := VariableInfo(parts[0])
	if !found {
		return nil, false
	}
	typ := meta.Type
	if inner, isList := strings.CutPrefix(typ, "list("); isList {
		typ = strings.TrimSuffix(inner, ")")
	}
	md, found := variableMessageTypes[typ]
	if !found {
		return nil, false
	}

	// Descend nested message fields for paths like "target.provenance".
	for _, fieldName := range parts[1:] {
		fd := md.Fields().ByName(protoreflect.Name(fieldName))
		if fd == nil || fd.Kind() != protoreflect.MessageKind || fd.IsMap() {
			return nil, false
		}
		md = fd.Message()
	}

	fds := md.Fields()
	fields = make([]string, 0, fds.Len())
	for i := 0; i < fds.Len(); i++ {
		fields = append(fields, string(fds.Get(i).Name()))
	}
	slices.Sort(fields)
	return fields, true
}
