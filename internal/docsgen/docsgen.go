// Package docsgen renders reference documentation sections from Deputy's
// registries and proto descriptors, so the docs derive from the same sources
// the API, MCP, and LSP surfaces serve instead of hand-maintained tables that
// drift. Generated sections live between BEGIN/END GENERATED markers inside
// otherwise hand-written documents; a drift test keeps the committed docs in
// lockstep with the sources.
package docsgen

//go:generate go run ./cmd

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/policy"
	"github.com/temporalio/deputy/internal/proto/descriptorset"
)

// PolicyEntrypointsSection names the generated policy entrypoint reference
// section. The markers on disk look like:
//
//	<!-- BEGIN GENERATED: policy-entrypoints -->
//	<!-- END GENERATED: policy-entrypoints -->
const PolicyEntrypointsSection = "policy-entrypoints"

// CanonicalEcosystemsSection names the generated canonical ecosystem table.
// The markers on disk look like:
//
//	<!-- BEGIN GENERATED: canonical-ecosystems -->
//	<!-- END GENERATED: canonical-ecosystems -->
const CanonicalEcosystemsSection = "canonical-ecosystems"

// PolicyInputsDocPath is the documentation file that carries the generated
// policy entrypoint reference, relative to the repository root.
const PolicyInputsDocPath = "docs/reference/policy-inputs.md"

// CanonicalEcosystemsMarkdown renders the ecosystem vocabulary policies compare
// against: every canonical token with the display name Deputy renders for it.
// Both come from the ecosystem registry, so adding an ecosystem updates the
// docs instead of leaving a hand-copied list to drift.
func CanonicalEcosystemsMarkdown() string {
	var b strings.Builder
	b.WriteString("| Canonical token | Display name |\n")
	b.WriteString("| --- | --- |\n")
	for _, token := range ecosystem.CanonicalEcosystems() {
		b.WriteString(fmt.Sprintf("| `%s` | %s |\n", token, tableCell(ecosystem.Display(ecosystem.Ecosystem(token)))))
	}
	return b.String()
}

// PolicyEntrypointsMarkdown renders the policy entrypoint reference: every
// entrypoint's variables from the binding-profile registry, and the
// proto-backed variable types' fields from proto descriptor comments.
func PolicyEntrypointsMarkdown() string {
	var b strings.Builder

	b.WriteString("## Entrypoint reference\n\n")
	b.WriteString("Each entrypoint's variables come from the policy binding registry, the\n")
	b.WriteString("same source the `deputy policy` API, the MCP `list_policy_entrypoints`\n")
	b.WriteString("tool, and the policy LSP serve. Required variables are always bound;\n")
	b.WriteString("guard optional variables with CEL optional syntax (`?.field.orValue()`).\n\n")

	categories := policy.Categories()
	for _, category := range categories {
		b.WriteString(fmt.Sprintf("### Category: `%s`\n\n", category))
		for _, ep := range policy.AllEntrypoints {
			if ep.Category() != category {
				continue
			}
			writeEntrypoint(&b, ep)
		}
	}

	b.WriteString("## Variable types\n\n")
	b.WriteString("Proto-backed variable types expose the fields below; CEL uses the\n")
	b.WriteString("snake_case proto field names. Field descriptions come from the proto\n")
	b.WriteString("comments in [`api/deputy`](../../api/deputy).\n\n")
	for _, typeName := range policy.ProtoVariableTypeNames() {
		md, ok := policy.VariableMessageDescriptor(typeName)
		if !ok {
			continue
		}
		b.WriteString(fmt.Sprintf("### `%s`\n\n", typeName))
		if comment := descriptorset.Summary(md.FullName()); comment != "" {
			b.WriteString(comment + "\n\n")
		}
		writeFieldTable(&b, md)
	}

	return strings.TrimRight(b.String(), "\n") + "\n"
}

// writeEntrypoint renders one entrypoint's description, helpers, and variable
// table.
func writeEntrypoint(b *strings.Builder, ep policy.Entrypoint) {
	profile := policy.GetBindingProfile(ep)

	b.WriteString(fmt.Sprintf("#### `%s`\n\n", string(ep)))
	if profile != nil && profile.Description != "" {
		b.WriteString(profile.Description + "\n\n")
	}

	if helpers := policy.EntrypointHelpers(ep); len(helpers) > 0 {
		quoted := make([]string, len(helpers))
		for i, h := range helpers {
			quoted[i] = "`" + h + "`"
		}
		b.WriteString("Helpers: " + strings.Join(quoted, ", ") + "\n\n")
	}

	if profile == nil || (len(profile.Required) == 0 && len(profile.Optional) == 0) {
		return
	}

	b.WriteString("| Variable | Type | Required | Description |\n")
	b.WriteString("| --- | --- | --- | --- |\n")
	for _, name := range profile.Required {
		writeVariableRow(b, name, true)
	}
	for _, name := range profile.Optional {
		writeVariableRow(b, name, false)
	}
	b.WriteString("\n")
}

// writeVariableRow renders one variable table row from the shared variable
// metadata registry.
func writeVariableRow(b *strings.Builder, name string, required bool) {
	meta := policy.VariableInfoOrDefault(name)
	requiredCell := "no"
	if required {
		requiredCell = "yes"
	}
	fmt.Fprintf(b, "| `%s` | `%s` | %s | %s |\n", name, meta.Type, requiredCell, tableCell(meta.Description))
}

// writeFieldTable renders a message descriptor's top-level fields with their
// proto comments.
func writeFieldTable(b *strings.Builder, md protoreflect.MessageDescriptor) {
	b.WriteString("| Field | Type | Description |\n")
	b.WriteString("| --- | --- | --- |\n")
	fields := md.Fields()
	names := make([]string, 0, fields.Len())
	byName := make(map[string]protoreflect.FieldDescriptor, fields.Len())
	for i := range fields.Len() {
		fd := fields.Get(i)
		names = append(names, string(fd.Name()))
		byName[string(fd.Name())] = fd
	}
	slices.Sort(names)
	for _, name := range names {
		fd := byName[name]
		fmt.Fprintf(b, "| `%s` | `%s` | %s |\n", name, fieldTypeString(fd), tableCell(descriptorset.Summary(fd.FullName())))
	}
	b.WriteString("\n")
}

// fieldTypeString renders a field's CEL-facing type: scalars by kind, message
// fields by their short proto name, lists and maps by their element types.
func fieldTypeString(fd protoreflect.FieldDescriptor) string {
	if fd.IsMap() {
		return fmt.Sprintf("map(%s, %s)", scalarTypeString(fd.MapKey()), scalarTypeString(fd.MapValue()))
	}
	if fd.IsList() {
		return fmt.Sprintf("list(%s)", scalarTypeString(fd))
	}
	return scalarTypeString(fd)
}

// scalarTypeString renders a non-repeated field's type name.
func scalarTypeString(fd protoreflect.FieldDescriptor) string {
	switch fd.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return string(fd.Message().Name())
	case protoreflect.EnumKind:
		return string(fd.Enum().Name())
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind,
		protoreflect.Uint32Kind, protoreflect.Fixed32Kind,
		protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return "int"
	case protoreflect.FloatKind, protoreflect.DoubleKind:
		return "double"
	default:
		return fd.Kind().String()
	}
}

// tableCell escapes a string for use in a markdown table cell: pipes are
// escaped and newlines flattened so a cell can never break the table.
func tableCell(s string) string {
	s = strings.ReplaceAll(strings.TrimSpace(s), "\n", " ")
	return strings.ReplaceAll(s, "|", "\\|")
}

// UpdateSection replaces the named generated section of a file in place. The
// file must already contain the BEGIN/END markers; content outside them is
// untouched.
func UpdateSection(path, section, content string) error {
	begin := fmt.Sprintf("<!-- BEGIN GENERATED: %s -->", section)
	end := fmt.Sprintf("<!-- END GENERATED: %s -->", section)

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	src := string(data)

	beginIdx := strings.Index(src, begin)
	endIdx := strings.Index(src, end)
	if beginIdx == -1 || endIdx == -1 || endIdx < beginIdx {
		return fmt.Errorf("%s: missing %q/%q markers", path, begin, end)
	}

	updated := src[:beginIdx+len(begin)] + "\n" + content + end + src[endIdx+len(end):]
	if updated == src {
		return nil
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// Section returns the current content of the named generated section of a
// file, without the markers.
func Section(path, section string) (string, error) {
	begin := fmt.Sprintf("<!-- BEGIN GENERATED: %s -->", section)
	end := fmt.Sprintf("<!-- END GENERATED: %s -->", section)

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	src := string(data)
	beginIdx := strings.Index(src, begin)
	endIdx := strings.Index(src, end)
	if beginIdx == -1 || endIdx == -1 || endIdx < beginIdx {
		return "", fmt.Errorf("%s: missing %q/%q markers", path, begin, end)
	}
	return strings.TrimPrefix(src[beginIdx+len(begin):endIdx], "\n"), nil
}
