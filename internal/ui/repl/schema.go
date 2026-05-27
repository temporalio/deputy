// Package repl provides a world-class interactive REPL for CEL policy evaluation.
//
// The REPL features:
//   - Proto-driven schema introspection for precise, contextual hints
//   - Tab completion with type-aware suggestions
//   - Inline hints showing field types and documentation
//   - Syntax highlighting for CEL expressions
//   - Beautiful theming with lipgloss
//   - Extensible completion providers
package repl

import (
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
	graphv1 "github.com/temporalio/deputy/gen/deputy/graph/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

// SchemaRegistry provides proto schema introspection for CEL hints.
// It maps CEL variable names to their proto message descriptors,
// enabling precise, type-aware completions.
type SchemaRegistry struct {
	// variables maps CEL variable names to their schemas
	variables map[string]*VariableSchema

	// enums maps enum type names to their values
	enums map[string]*EnumSchema

	// functions contains helper function signatures
	functions []FunctionSchema
}

// VariableSchema describes a CEL variable's type and fields.
type VariableSchema struct {
	Name        string         // CEL variable name
	Description string         // Human-readable description
	Type        string         // Type name (message, map, list, scalar)
	Fields      []*FieldSchema // Fields if message type
	ProtoDesc   protoreflect.MessageDescriptor
}

// FieldSchema describes a field within a proto message.
type FieldSchema struct {
	Name        string // Field name (snake_case converted to camelCase for CEL)
	CELName     string // Name as it appears in CEL
	Type        string // Type description
	Description string // From proto comments
	Repeated    bool   // Is this a repeated field
	Optional    bool   // Is this an optional field
	MapKey      string // If map, the key type
	MapValue    string // If map, the value type
	MessageType string // If message, the message type name
	EnumType    string // If enum, the enum type name
}

// EnumSchema describes a proto enum type.
type EnumSchema struct {
	Name        string       // Enum type name
	Description string       // Human-readable description
	Values      []EnumValue  // Enum values
	CELPrefix   string       // How to access in CEL (e.g., "severity.")
}

// EnumValue describes a single enum value.
type EnumValue struct {
	Name        string // Value name (without prefix)
	Number      int32  // Numeric value
	Description string // Human-readable description
}

// FunctionSchema describes a CEL helper function.
type FunctionSchema struct {
	Name        string   // Function name
	Signature   string   // Full signature
	Description string   // What the function does
	Parameters  []string // Parameter names for hints
	ReturnType  string   // Return type
	Category    string   // Grouping category
}

// NewSchemaRegistry creates a schema registry with Deputy's proto schemas.
func NewSchemaRegistry() *SchemaRegistry {
	r := &SchemaRegistry{
		variables: make(map[string]*VariableSchema),
		enums:     make(map[string]*EnumSchema),
	}

	// Register vulnerability schemas
	r.registerVulnerabilitySchemas()

	// Register graph schemas
	r.registerGraphSchemas()

	// Register scan schemas
	r.registerScanSchemas()

	// Register container schemas
	r.registerContainerSchemas()

	// Register enums
	r.registerEnums()

	// Register REPL-specific variables (request, env, jwt, etc.)
	r.registerREPLVariables()

	// Register helper functions
	r.registerFunctions()

	return r
}

// registerVulnerabilitySchemas adds vulnerability-related schemas.
func (r *SchemaRegistry) registerVulnerabilitySchemas() {
	// Finding (vulnerability in scan results)
	findingDesc := (&vulnerabilityv1.Finding{}).ProtoReflect().Descriptor()
	r.variables["vulnerability"] = r.messageToSchema("vulnerability", findingDesc,
		"A vulnerability finding from a scan")

	// Advisory
	advisoryDesc := (&vulnerabilityv1.Advisory{}).ProtoReflect().Descriptor()
	r.variables["advisory"] = r.messageToSchema("advisory", advisoryDesc,
		"Vulnerability advisory details")

	// Stats
	statsDesc := (&vulnerabilityv1.Stats{}).ProtoReflect().Descriptor()
	r.variables["vuln_stats"] = r.messageToSchema("vuln_stats", statsDesc,
		"Vulnerability statistics summary")
}

// registerGraphSchemas adds graph-related schemas.
func (r *SchemaRegistry) registerGraphSchemas() {
	// Node
	nodeDesc := (&graphv1.Node{}).ProtoReflect().Descriptor()
	r.variables["node"] = r.messageToSchema("node", nodeDesc,
		"A dependency node in the graph")

	// Edge
	edgeDesc := (&graphv1.Edge{}).ProtoReflect().Descriptor()
	r.variables["edge"] = r.messageToSchema("edge", edgeDesc,
		"A dependency edge (relationship)")

	// GraphStats
	graphStatsDesc := (&graphv1.GraphStats{}).ProtoReflect().Descriptor()
	r.variables["stats"] = r.messageToSchema("stats", graphStatsDesc,
		"Graph statistics")
}

// registerScanSchemas adds scan-related schemas.
func (r *SchemaRegistry) registerScanSchemas() {
	// ScanOptions
	optionsDesc := (&scanv1.ScanOptions{}).ProtoReflect().Descriptor()
	r.variables["scan_options"] = r.messageToSchema("scan_options", optionsDesc,
		"Scan configuration options")
}

// registerContainerSchemas adds container-related schemas.
func (r *SchemaRegistry) registerContainerSchemas() {
	// ImageConfig
	configDesc := (&containerv1.ImageConfig{}).ProtoReflect().Descriptor()
	r.variables["image.config"] = r.messageToSchema("image.config", configDesc,
		"Container image configuration")

	// ImageMetadata
	metaDesc := (&containerv1.ImageMetadata{}).ProtoReflect().Descriptor()
	r.variables["image.metadata"] = r.messageToSchema("image.metadata", metaDesc,
		"Container image metadata")
}

// registerEnums adds enum schemas.
func (r *SchemaRegistry) registerEnums() {
	// SeverityLevel
	r.enums["severity"] = &EnumSchema{
		Name:        "SeverityLevel",
		Description: "Vulnerability severity levels",
		CELPrefix:   "severity.",
		Values: []EnumValue{
			{Name: "CRITICAL", Number: 4, Description: "Critical severity (CVSS 9.0-10.0)"},
			{Name: "HIGH", Number: 3, Description: "High severity (CVSS 7.0-8.9)"},
			{Name: "MEDIUM", Number: 2, Description: "Medium severity (CVSS 4.0-6.9)"},
			{Name: "LOW", Number: 1, Description: "Low severity (CVSS 0.1-3.9)"},
			{Name: "UNSPECIFIED", Number: 0, Description: "Unknown severity"},
		},
	}

	// Scope
	r.enums["scope"] = &EnumSchema{
		Name:        "Scope",
		Description: "Dependency scope",
		CELPrefix:   "scope.",
		Values: []EnumValue{
			{Name: "RUNTIME", Number: 1, Description: "Runtime dependency"},
			{Name: "DEV", Number: 2, Description: "Development dependency"},
			{Name: "TEST", Number: 5, Description: "Test dependency"},
			{Name: "BUILD", Number: 4, Description: "Build-time dependency"},
			{Name: "OPTIONAL", Number: 3, Description: "Optional dependency"},
			{Name: "UNSPECIFIED", Number: 0, Description: "Unspecified scope"},
		},
	}
}

// registerREPLVariables adds common REPL variables that don't come from protos.
func (r *SchemaRegistry) registerREPLVariables() {
	// request - the current request context in proxy/policy evaluation
	r.variables["request"] = &VariableSchema{
		Name:        "request",
		Description: "Request context with package/module information",
		Type:        "map",
		Fields: []*FieldSchema{
			{Name: "ecosystem", CELName: "ecosystem", Type: "string", Description: "Package ecosystem (npm, go, pypi, etc.)"},
			{Name: "package", CELName: "package", Type: "string", Description: "Package name"},
			{Name: "module", CELName: "module", Type: "string", Description: "Module path (Go)"},
			{Name: "version", CELName: "version", Type: "string", Description: "Package version"},
			{Name: "license", CELName: "license", Type: "string", Description: "License identifier"},
		},
	}

	// env - environment context
	r.variables["env"] = &VariableSchema{
		Name:        "env",
		Description: "Environment context",
		Type:        "map",
		Fields: []*FieldSchema{
			{Name: "command", CELName: "command", Type: "string", Description: "Deputy command (scan, proxy, etc.)"},
			{Name: "entrypoint", CELName: "entrypoint", Type: "string", Description: "Policy entrypoint being evaluated"},
		},
	}

	// jwt - JWT claims (for authenticated requests)
	r.variables["jwt"] = &VariableSchema{
		Name:        "jwt",
		Description: "JWT claims from authenticated requests",
		Type:        "map",
		Fields: []*FieldSchema{
			{Name: "anonymous", CELName: "anonymous", Type: "bool", Description: "True if no token provided"},
			{Name: "sub", CELName: "sub", Type: "string", Description: "Subject (user/service ID)"},
			{Name: "iss", CELName: "iss", Type: "string", Description: "Token issuer"},
			{Name: "aud", CELName: "aud", Type: "list", Description: "Audiences", Repeated: true},
			{Name: "exp", CELName: "exp", Type: "int", Description: "Expiration timestamp"},
			{Name: "iat", CELName: "iat", Type: "int", Description: "Issued-at timestamp"},
			{Name: "roles", CELName: "roles", Type: "list", Description: "User roles", Repeated: true},
			{Name: "teams", CELName: "teams", Type: "list", Description: "User teams", Repeated: true},
		},
	}

	// pkg - package context (for scan policies)
	r.variables["pkg"] = &VariableSchema{
		Name:        "pkg",
		Description: "Package being analyzed",
		Type:        "map",
		Fields: []*FieldSchema{
			{Name: "name", CELName: "name", Type: "string", Description: "Package name"},
			{Name: "version", CELName: "version", Type: "string", Description: "Package version"},
			{Name: "ecosystem", CELName: "ecosystem", Type: "string", Description: "Package ecosystem"},
			{Name: "licenses", CELName: "licenses", Type: "list", Description: "SPDX license identifiers", Repeated: true},
		},
	}

	// vulnerabilities - list of vulnerability findings
	r.variables["vulnerabilities"] = &VariableSchema{
		Name:        "vulnerabilities",
		Description: "List of vulnerability findings from scan",
		Type:        "list",
		Fields:      r.variables["vulnerability"].Fields, // Reuse vulnerability fields
	}

	// image - container image context
	r.variables["image"] = &VariableSchema{
		Name:        "image",
		Description: "Container image information",
		Type:        "map",
		Fields: []*FieldSchema{
			{Name: "registry", CELName: "registry", Type: "string", Description: "Registry hostname"},
			{Name: "repository", CELName: "repository", Type: "string", Description: "Repository path"},
			{Name: "tag", CELName: "tag", Type: "string", Description: "Image tag"},
			{Name: "digest", CELName: "digest", Type: "string", Description: "Image digest"},
			{Name: "config", CELName: "config", Type: "message", MessageType: "ImageConfig", Description: "Image configuration"},
			{Name: "metadata", CELName: "metadata", Type: "message", MessageType: "ImageMetadata", Description: "Image metadata"},
			{Name: "history", CELName: "history", Type: "list", Description: "Build history entries", Repeated: true},
		},
	}

	// nodes - list of graph nodes
	r.variables["nodes"] = &VariableSchema{
		Name:        "nodes",
		Description: "List of dependency graph nodes",
		Type:        "list",
		Fields:      r.variables["node"].Fields,
	}

	// edges - list of graph edges
	r.variables["edges"] = &VariableSchema{
		Name:        "edges",
		Description: "List of dependency graph edges",
		Type:        "list",
		Fields:      r.variables["edge"].Fields,
	}

	// roots - list of root (direct) dependencies
	r.variables["roots"] = &VariableSchema{
		Name:        "roots",
		Description: "List of root (direct) dependencies",
		Type:        "list",
	}
}

// registerFunctions adds helper function schemas.
func (r *SchemaRegistry) registerFunctions() {
	r.functions = []FunctionSchema{
		// Severity functions
		{Name: "severityAtLeast", Signature: "severityAtLeast(vulnerability, level) bool",
			Description: "Check if severity >= level", Parameters: []string{"vulnerability", "level"},
			ReturnType: "bool", Category: "severity"},
		{Name: "isCritical", Signature: "isCritical(vulnerability) bool",
			Description: "Check if severity is CRITICAL", Parameters: []string{"vulnerability"},
			ReturnType: "bool", Category: "severity"},
		{Name: "isHighOrAbove", Signature: "isHighOrAbove(vulnerability) bool",
			Description: "Check if severity is HIGH or CRITICAL", Parameters: []string{"vulnerability"},
			ReturnType: "bool", Category: "severity"},
		{Name: "vulnerabilitySeverity", Signature: "vulnerabilitySeverity(vulnerability) string",
			Description: "Get severity level string", Parameters: []string{"vulnerability"},
			ReturnType: "string", Category: "severity"},

		// Graph functions
		{Name: "isDirectDep", Signature: "isDirectDep(node) bool",
			Description: "Check if node is direct dependency", Parameters: []string{"node"},
			ReturnType: "bool", Category: "graph"},
		{Name: "nodeDepth", Signature: "nodeDepth(node) int",
			Description: "Get dependency depth (0=direct)", Parameters: []string{"node"},
			ReturnType: "int", Category: "graph"},
		{Name: "nodeEcosystem", Signature: "nodeEcosystem(node) string",
			Description: "Get package ecosystem", Parameters: []string{"node"},
			ReturnType: "string", Category: "graph"},
		{Name: "hasVulnerabilities", Signature: "hasVulnerabilities(node) bool",
			Description: "Check if node has vulnerabilities", Parameters: []string{"node"},
			ReturnType: "bool", Category: "graph"},
		{Name: "vulnerabilityCount", Signature: "vulnerabilityCount(node) int",
			Description: "Get vulnerability count", Parameters: []string{"node"},
			ReturnType: "int", Category: "graph"},
		{Name: "graphMatch", Signature: "graphMatch(string, pattern) bool",
			Description: "Glob pattern matching", Parameters: []string{"string", "pattern"},
			ReturnType: "bool", Category: "graph"},

		// Time functions
		{Name: "now", Signature: "now() timestamp",
			Description: "Current time", Parameters: nil,
			ReturnType: "timestamp", Category: "time"},
		{Name: "age", Signature: "age(timestamp) duration",
			Description: "Duration since timestamp", Parameters: []string{"timestamp"},
			ReturnType: "duration", Category: "time"},

		// String functions (CEL stdlib)
		{Name: "contains", Signature: "string.contains(substring) bool",
			Description: "Check if string contains substring", Parameters: []string{"substring"},
			ReturnType: "bool", Category: "string"},
		{Name: "startsWith", Signature: "string.startsWith(prefix) bool",
			Description: "Check if string starts with prefix", Parameters: []string{"prefix"},
			ReturnType: "bool", Category: "string"},
		{Name: "endsWith", Signature: "string.endsWith(suffix) bool",
			Description: "Check if string ends with suffix", Parameters: []string{"suffix"},
			ReturnType: "bool", Category: "string"},
		{Name: "matches", Signature: "string.matches(regex) bool",
			Description: "Regex match", Parameters: []string{"regex"},
			ReturnType: "bool", Category: "string"},

		// List macros (CEL stdlib)
		{Name: "exists", Signature: "list.exists(x, predicate) bool",
			Description: "Any element matches predicate", Parameters: []string{"x", "predicate"},
			ReturnType: "bool", Category: "list"},
		{Name: "all", Signature: "list.all(x, predicate) bool",
			Description: "All elements match predicate", Parameters: []string{"x", "predicate"},
			ReturnType: "bool", Category: "list"},
		{Name: "filter", Signature: "list.filter(x, predicate) list",
			Description: "Filter elements by predicate", Parameters: []string{"x", "predicate"},
			ReturnType: "list", Category: "list"},
		{Name: "map", Signature: "list.map(x, expr) list",
			Description: "Transform elements", Parameters: []string{"x", "expr"},
			ReturnType: "list", Category: "list"},

		// PURL function
		{Name: "purl", Signature: "purl(string) map",
			Description: "Parse Package URL", Parameters: []string{"purl_string"},
			ReturnType: "map", Category: "package"},

		// Image functions
		{Name: "imageRef", Signature: "imageRef(string) map",
			Description: "Parse container image reference", Parameters: []string{"reference"},
			ReturnType: "map", Category: "container"},
		{Name: "baseImage", Signature: "baseImage(history) string",
			Description: "Extract base image from history", Parameters: []string{"history"},
			ReturnType: "string", Category: "container"},

		// SSVC function
		{Name: "ssvc", Signature: "ssvc(vulnerability) map",
			Description: "SSVC decision tree evaluation", Parameters: []string{"vulnerability"},
			ReturnType: "map", Category: "vulnerability"},
	}
}

// messageToSchema converts a proto message descriptor to a VariableSchema.
func (r *SchemaRegistry) messageToSchema(name string, desc protoreflect.MessageDescriptor, description string) *VariableSchema {
	schema := &VariableSchema{
		Name:        name,
		Description: description,
		Type:        "message",
		ProtoDesc:   desc,
		Fields:      make([]*FieldSchema, 0, desc.Fields().Len()),
	}

	fields := desc.Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		field := r.fieldToSchema(fd)
		schema.Fields = append(schema.Fields, field)
	}

	return schema
}

// fieldToSchema converts a proto field descriptor to a FieldSchema.
func (r *SchemaRegistry) fieldToSchema(fd protoreflect.FieldDescriptor) *FieldSchema {
	field := &FieldSchema{
		Name:     string(fd.Name()),
		CELName:  toCamelCase(string(fd.Name())),
		Repeated: fd.IsList(),
		Optional: fd.HasOptionalKeyword(),
	}

	// Determine type
	switch fd.Kind() {
	case protoreflect.BoolKind:
		field.Type = "bool"
	case protoreflect.Int32Kind, protoreflect.Int64Kind,
		protoreflect.Sint32Kind, protoreflect.Sint64Kind,
		protoreflect.Sfixed32Kind, protoreflect.Sfixed64Kind:
		field.Type = "int"
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind,
		protoreflect.Fixed32Kind, protoreflect.Fixed64Kind:
		field.Type = "uint"
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		field.Type = "double"
	case protoreflect.StringKind:
		field.Type = "string"
	case protoreflect.BytesKind:
		field.Type = "bytes"
	case protoreflect.EnumKind:
		field.Type = "enum"
		field.EnumType = string(fd.Enum().Name())
	case protoreflect.MessageKind:
		if fd.IsMap() {
			field.Type = "map"
			field.MapKey = kindToString(fd.MapKey().Kind())
			field.MapValue = kindToString(fd.MapValue().Kind())
			if fd.MapValue().Kind() == protoreflect.MessageKind {
				field.MapValue = string(fd.MapValue().Message().Name())
			}
		} else {
			field.Type = "message"
			field.MessageType = string(fd.Message().Name())
			// Handle well-known types
			switch fd.Message().FullName() {
			case "google.protobuf.Timestamp":
				field.Type = "timestamp"
			case "google.protobuf.Duration":
				field.Type = "duration"
			}
		}
	}

	return field
}

// GetVariable returns the schema for a CEL variable.
func (r *SchemaRegistry) GetVariable(name string) *VariableSchema {
	return r.variables[name]
}

// GetEnum returns the schema for an enum type.
func (r *SchemaRegistry) GetEnum(name string) *EnumSchema {
	return r.enums[name]
}

// GetFunctions returns all function schemas.
func (r *SchemaRegistry) GetFunctions() []FunctionSchema {
	return r.functions
}

// GetFunctionsByCategory returns functions in a category.
func (r *SchemaRegistry) GetFunctionsByCategory(category string) []FunctionSchema {
	var funcs []FunctionSchema
	for _, f := range r.functions {
		if f.Category == category {
			funcs = append(funcs, f)
		}
	}
	return funcs
}

// VariableNames returns all registered variable names.
func (r *SchemaRegistry) VariableNames() []string {
	names := make([]string, 0, len(r.variables))
	for name := range r.variables {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// EnumNames returns all registered enum names.
func (r *SchemaRegistry) EnumNames() []string {
	names := make([]string, 0, len(r.enums))
	for name := range r.enums {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// FunctionCategories returns all function category names.
func (r *SchemaRegistry) FunctionCategories() []string {
	cats := make(map[string]bool)
	for _, f := range r.functions {
		cats[f.Category] = true
	}
	result := make([]string, 0, len(cats))
	for cat := range cats {
		result = append(result, cat)
	}
	sort.Strings(result)
	return result
}

// toCamelCase converts snake_case to camelCase.
func toCamelCase(s string) string {
	parts := strings.Split(s, "_")
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) > 0 {
			parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
		}
	}
	return strings.Join(parts, "")
}

// kindToString converts a proto kind to a string name.
func kindToString(k protoreflect.Kind) string {
	switch k {
	case protoreflect.BoolKind:
		return "bool"
	case protoreflect.Int32Kind, protoreflect.Int64Kind:
		return "int"
	case protoreflect.Uint32Kind, protoreflect.Uint64Kind:
		return "uint"
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return "double"
	case protoreflect.StringKind:
		return "string"
	case protoreflect.BytesKind:
		return "bytes"
	default:
		return "unknown"
	}
}

// FormatFieldType returns a human-readable type description for a field.
func (f *FieldSchema) FormatFieldType() string {
	var typ string
	switch f.Type {
	case "map":
		typ = fmt.Sprintf("map<%s, %s>", f.MapKey, f.MapValue)
	case "message":
		typ = f.MessageType
	case "enum":
		typ = f.EnumType
	default:
		typ = f.Type
	}
	if f.Repeated {
		typ = "list<" + typ + ">"
	}
	if f.Optional {
		typ = typ + "?"
	}
	return typ
}
