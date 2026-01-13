package repl

import (
	"sort"
	"strings"
	"unicode"
)

// Completion represents a single completion suggestion.
type Completion struct {
	Text        string // The completion text to insert
	Display     string // How to display (may include type info)
	Description string // Short description/documentation
	Kind        CompletionKind
	Score       int // For ranking (higher = better match)
}

// CompletionKind categorizes completions for styling.
type CompletionKind int

const (
	CompletionVariable CompletionKind = iota
	CompletionField
	CompletionFunction
	CompletionEnum
	CompletionKeyword
	CompletionOperator
)

// String returns the kind name.
func (k CompletionKind) String() string {
	switch k {
	case CompletionVariable:
		return "var"
	case CompletionField:
		return "field"
	case CompletionFunction:
		return "func"
	case CompletionEnum:
		return "enum"
	case CompletionKeyword:
		return "keyword"
	case CompletionOperator:
		return "op"
	default:
		return "?"
	}
}

// Symbol returns a unicode symbol for the kind.
func (k CompletionKind) Symbol() string {
	switch k {
	case CompletionVariable:
		return "•" // bullet for variables
	case CompletionField:
		return "·" // middle dot for fields
	case CompletionFunction:
		return "ƒ" // function symbol
	case CompletionEnum:
		return "▪" // small square for enums
	case CompletionKeyword:
		return "◇" // small diamond for keywords
	case CompletionOperator:
		return "∘" // ring operator for operators
	default:
		return "·"
	}
}

// CompletionEngine provides contextual completions for CEL expressions.
type CompletionEngine struct {
	schema   *SchemaRegistry
	keywords []string
	operators []string
}

// NewCompletionEngine creates a completion engine backed by the schema registry.
func NewCompletionEngine(schema *SchemaRegistry) *CompletionEngine {
	return &CompletionEngine{
		schema: schema,
		keywords: []string{
			"true", "false", "null",
			"in", "has",
		},
		operators: []string{
			"&&", "||", "!",
			"==", "!=", "<", "<=", ">", ">=",
			"+", "-", "*", "/", "%",
			"?", ":",
		},
	}
}

// Complete returns completions for the given input at the cursor position.
func (e *CompletionEngine) Complete(input string, cursor int) []Completion {
	if cursor > len(input) {
		cursor = len(input)
	}

	// Analyze context
	ctx := e.analyzeContext(input, cursor)

	var completions []Completion

	switch ctx.Kind {
	case contextDot:
		// Field access: variable.| or variable.field.|
		completions = e.completeFields(ctx.Base, ctx.Partial)

	case contextEnum:
		// Enum access: severity.| or scope.|
		completions = e.completeEnumValues(ctx.Base, ctx.Partial)

	case contextFunction:
		// Function call: funcName(|
		completions = e.completeFunctionArgs(ctx.Function)

	case contextRoot:
		// Root context: |, or partial|
		completions = e.completeRoot(ctx.Partial)
	}

	// Sort by score then alphabetically
	sort.Slice(completions, func(i, j int) bool {
		if completions[i].Score != completions[j].Score {
			return completions[i].Score > completions[j].Score
		}
		return completions[i].Text < completions[j].Text
	})

	return completions
}

// contextKind identifies what kind of completion context we're in.
type contextKind int

const (
	contextRoot contextKind = iota
	contextDot
	contextEnum
	contextFunction
)

// completionContext holds parsed context information.
type completionContext struct {
	Kind     contextKind
	Base     string // Base identifier (before .)
	Partial  string // Partial text being completed
	Function string // Function name if in function context
}

// analyzeContext parses the input to determine completion context.
func (e *CompletionEngine) analyzeContext(input string, cursor int) completionContext {
	if cursor == 0 {
		return completionContext{Kind: contextRoot}
	}

	// Get text before cursor
	before := input[:cursor]

	// Find the current token start
	tokenStart := cursor
	for tokenStart > 0 {
		r := rune(before[tokenStart-1])
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '.' {
			break
		}
		tokenStart--
	}
	currentToken := before[tokenStart:]

	// Check if we're after a dot
	if dotIdx := strings.LastIndex(currentToken, "."); dotIdx >= 0 {
		base := currentToken[:dotIdx]
		partial := currentToken[dotIdx+1:]

		// Check if base is an enum
		if _, ok := e.schema.enums[base]; ok {
			return completionContext{
				Kind:    contextEnum,
				Base:    base,
				Partial: partial,
			}
		}

		// Otherwise it's field access
		return completionContext{
			Kind:    contextDot,
			Base:    base,
			Partial: partial,
		}
	}

	// Check if we're inside a function call
	parenIdx := strings.LastIndex(before, "(")
	if parenIdx > 0 {
		// Find function name before paren
		funcEnd := parenIdx
		funcStart := funcEnd
		for funcStart > 0 {
			r := rune(before[funcStart-1])
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
				break
			}
			funcStart--
		}
		if funcStart < funcEnd {
			funcName := before[funcStart:funcEnd]
			return completionContext{
				Kind:     contextFunction,
				Function: funcName,
				Partial:  currentToken,
			}
		}
	}

	// Root context
	return completionContext{
		Kind:    contextRoot,
		Partial: currentToken,
	}
}

// completeRoot provides completions at root level.
func (e *CompletionEngine) completeRoot(partial string) []Completion {
	var completions []Completion
	partialLower := strings.ToLower(partial)

	// Variables
	for _, name := range e.schema.VariableNames() {
		if matchesPrefix(name, partialLower) {
			schema := e.schema.GetVariable(name)
			completions = append(completions, Completion{
				Text:        name,
				Display:     name,
				Description: schema.Description,
				Kind:        CompletionVariable,
				Score:       scoreMatch(name, partial),
			})
		}
	}

	// Enum namespaces
	for _, name := range e.schema.EnumNames() {
		if matchesPrefix(name, partialLower) {
			schema := e.schema.GetEnum(name)
			completions = append(completions, Completion{
				Text:        name,
				Display:     name,
				Description: schema.Description,
				Kind:        CompletionEnum,
				Score:       scoreMatch(name, partial),
			})
		}
	}

	// Functions
	for _, fn := range e.schema.GetFunctions() {
		if matchesPrefix(fn.Name, partialLower) {
			completions = append(completions, Completion{
				Text:        fn.Name,
				Display:     fn.Signature,
				Description: fn.Description,
				Kind:        CompletionFunction,
				Score:       scoreMatch(fn.Name, partial),
			})
		}
	}

	// Keywords
	for _, kw := range e.keywords {
		if matchesPrefix(kw, partialLower) {
			completions = append(completions, Completion{
				Text:        kw,
				Display:     kw,
				Description: "keyword",
				Kind:        CompletionKeyword,
				Score:       scoreMatch(kw, partial),
			})
		}
	}

	return completions
}

// completeFields provides field completions for a base variable.
func (e *CompletionEngine) completeFields(base, partial string) []Completion {
	var completions []Completion
	partialLower := strings.ToLower(partial)

	// Handle nested field access (e.g., "vulnerability.advisory")
	schema := e.resolveVariableSchema(base)
	if schema == nil {
		return completions
	}

	for _, field := range schema.Fields {
		if matchesPrefix(field.CELName, partialLower) {
			completions = append(completions, Completion{
				Text:        field.CELName,
				Display:     field.CELName + " " + field.FormatFieldType(),
				Description: field.Description,
				Kind:        CompletionField,
				Score:       scoreMatch(field.CELName, partial),
			})
		}
	}

	return completions
}

// completeEnumValues provides enum value completions.
func (e *CompletionEngine) completeEnumValues(enumName, partial string) []Completion {
	var completions []Completion
	partialLower := strings.ToLower(partial)

	schema := e.schema.GetEnum(enumName)
	if schema == nil {
		return completions
	}

	for _, val := range schema.Values {
		if matchesPrefix(val.Name, partialLower) {
			completions = append(completions, Completion{
				Text:        val.Name,
				Display:     val.Name,
				Description: val.Description,
				Kind:        CompletionEnum,
				Score:       scoreMatch(val.Name, partial),
			})
		}
	}

	return completions
}

// completeFunctionArgs provides argument hints for a function call.
func (e *CompletionEngine) completeFunctionArgs(funcName string) []Completion {
	var completions []Completion

	for _, fn := range e.schema.GetFunctions() {
		if fn.Name == funcName {
			// Return variables that match expected parameter types
			for _, name := range e.schema.VariableNames() {
				schema := e.schema.GetVariable(name)
				completions = append(completions, Completion{
					Text:        name,
					Display:     name,
					Description: schema.Description,
					Kind:        CompletionVariable,
					Score:       100, // Boost variables in function context
				})
			}
			break
		}
	}

	return completions
}

// resolveVariableSchema resolves a potentially nested variable path to its schema.
func (e *CompletionEngine) resolveVariableSchema(path string) *VariableSchema {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return nil
	}

	// Try direct lookup first
	if schema := e.schema.GetVariable(path); schema != nil {
		return schema
	}

	// Try base variable
	base := parts[0]
	schema := e.schema.GetVariable(base)
	if schema == nil {
		return nil
	}

	// Navigate through fields
	for i := 1; i < len(parts); i++ {
		fieldName := parts[i]
		var found *FieldSchema
		for _, f := range schema.Fields {
			if f.CELName == fieldName || f.Name == fieldName {
				found = f
				break
			}
		}
		if found == nil {
			return nil
		}

		// If field is a message type, try to get its schema
		if found.MessageType != "" {
			// Try to find registered schema for this message type
			fullPath := strings.Join(parts[:i+1], ".")
			if nested := e.schema.GetVariable(fullPath); nested != nil {
				schema = nested
				continue
			}
		}

		// Can't navigate further
		return nil
	}

	return schema
}

// matchesPrefix checks if name matches the partial prefix (case-insensitive).
func matchesPrefix(name, partialLower string) bool {
	if partialLower == "" {
		return true
	}
	return strings.HasPrefix(strings.ToLower(name), partialLower)
}

// scoreMatch calculates a match score for ranking.
func scoreMatch(name, partial string) int {
	if partial == "" {
		return 50
	}
	nameLower := strings.ToLower(name)
	partialLower := strings.ToLower(partial)

	// Exact match
	if nameLower == partialLower {
		return 200
	}
	// Prefix match
	if strings.HasPrefix(nameLower, partialLower) {
		return 150 - len(name) // Prefer shorter names
	}
	// Contains match
	if strings.Contains(nameLower, partialLower) {
		return 100 - len(name)
	}
	return 0
}

// Hint represents an inline hint shown after the cursor.
type Hint struct {
	Text  string // The hint text
	Style string // Style name (for theming)
}

// GetHint returns a contextual hint for the current input.
func (e *CompletionEngine) GetHint(input string, cursor int) *Hint {
	if cursor > len(input) {
		cursor = len(input)
	}

	ctx := e.analyzeContext(input, cursor)

	switch ctx.Kind {
	case contextDot:
		// Show field type hint
		schema := e.resolveVariableSchema(ctx.Base)
		if schema != nil {
			for _, field := range schema.Fields {
				if strings.HasPrefix(strings.ToLower(field.CELName), strings.ToLower(ctx.Partial)) {
					return &Hint{
						Text:  " " + field.FormatFieldType(),
						Style: "hint",
					}
				}
			}
		}

	case contextEnum:
		// Show enum description
		schema := e.schema.GetEnum(ctx.Base)
		if schema != nil {
			for _, val := range schema.Values {
				if strings.HasPrefix(strings.ToLower(val.Name), strings.ToLower(ctx.Partial)) {
					return &Hint{
						Text:  " " + val.Description,
						Style: "hint",
					}
				}
			}
		}

	case contextFunction:
		// Show function signature
		for _, fn := range e.schema.GetFunctions() {
			if fn.Name == ctx.Function {
				return &Hint{
					Text:  " → " + fn.ReturnType,
					Style: "hint",
				}
			}
		}

	case contextRoot:
		// Show first matching completion as ghost text
		completions := e.Complete(input, cursor) // Use Complete to get sorted results
		if len(completions) > 0 && ctx.Partial != "" {
			best := completions[0]
			remaining := best.Text[len(ctx.Partial):]
			if remaining != "" {
				return &Hint{
					Text:  remaining,
					Style: "ghost",
				}
			}
		}
	}

	return nil
}

// DescribeVariable returns documentation for a variable path.
func (e *CompletionEngine) DescribeVariable(path string) string {
	schema := e.resolveVariableSchema(path)
	if schema == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(schema.Name)
	sb.WriteString(": ")
	sb.WriteString(schema.Description)
	sb.WriteString("\n\nFields:\n")

	for _, f := range schema.Fields {
		sb.WriteString("  ")
		sb.WriteString(f.CELName)
		sb.WriteString(" ")
		sb.WriteString(f.FormatFieldType())
		if f.Description != "" {
			sb.WriteString(" — ")
			sb.WriteString(f.Description)
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// DescribeFunction returns documentation for a function.
func (e *CompletionEngine) DescribeFunction(name string) string {
	for _, fn := range e.schema.GetFunctions() {
		if fn.Name == name {
			var sb strings.Builder
			sb.WriteString(fn.Signature)
			sb.WriteString("\n\n")
			sb.WriteString(fn.Description)
			return sb.String()
		}
	}
	return ""
}
