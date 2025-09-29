package sast

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

type rubyUnit struct {
	methods  []*rubyMethod
	types    map[string]*rubyType
	aliases  []rubyAlias
	requires []rubyRequire
}

type rubyMethodType int

const (
	rubyMethodTopLevel rubyMethodType = iota
	rubyMethodInstance
	rubyMethodClass
)

type rubyVisibility string

const (
	rubyVisibilityPublic    rubyVisibility = "public"
	rubyVisibilityPrivate   rubyVisibility = "private"
	rubyVisibilityProtected rubyVisibility = "protected"
)

type rubyMethod struct {
	name       string
	receiver   string
	typ        rubyMethodType
	location   Location
	calls      []rubyCall
	attributes map[string]any
	params     []rubyParam
	blockParam string
	hasBlock   bool
	yields     bool
}

type rubyCall struct {
	name           string
	receiver       string
	typ            rubyMethodType
	confidence     EdgeConfidence
	source         string
	symbolArgs     []string
	dynamic        bool
	metadata       map[string]any
	argCount       int
	hasBlock       bool
	yieldCall      bool
	argDescriptors []rubyArg
	blockParams    []string
	location       Location
}

type rubyParamKind int

const (
	rubyParamNormal rubyParamKind = iota
	rubyParamRest
	rubyParamKeyword
	rubyParamKeyRest
	rubyParamBlock
)

type rubyParam struct {
	name string
	kind rubyParamKind
}

func (k rubyParamKind) String() string {
	switch k {
	case rubyParamRest:
		return "rest"
	case rubyParamKeyword:
		return "keyword"
	case rubyParamKeyRest:
		return "keyrest"
	case rubyParamBlock:
		return "block"
	default:
		return "normal"
	}
}

type rubyArgKind string

const (
	rubyArgUnknown     rubyArgKind = "unknown"
	rubyArgParameter   rubyArgKind = "parameter"
	rubyArgIdentifier  rubyArgKind = "identifier"
	rubyArgLiteral     rubyArgKind = "literal"
	rubyArgSymbolArg   rubyArgKind = "symbol"
	rubyArgBlockPass   rubyArgKind = "blockpass"
	rubyArgSplat       rubyArgKind = "splat"
	rubyArgKeywordHash rubyArgKind = "keyword_hash"
)

type rubyArg struct {
	kind       rubyArgKind
	name       string
	raw        string
	paramIndex int
}

type callArgumentInfo struct {
	count       int
	hasBlock    bool
	args        []rubyArg
	blockParams []string
}

type rubyAlias struct {
	owner string
	new   string
	old   string
	typ   rubyMethodType
}

type rubyRequire struct {
	path string
	kind string
}

type rubyTypeKind string

const (
	rubyTypeClass  rubyTypeKind = "class"
	rubyTypeModule rubyTypeKind = "module"
)

type rubyType struct {
	Name            string
	Kind            rubyTypeKind
	Super           string
	Includes        []string
	Extends         []string
	Prepends        []string
	Visibility      map[string]rubyVisibility
	ModuleFunctions map[string]struct{}
	ModuleFnDefault bool
}

type rubyLexResult struct {
	tokens        []rubyToken
	genericTokens []Token
}

type rubyTokenKind int

const (
	rubyTokenEOF rubyTokenKind = iota
	rubyTokenNewline
	rubyTokenIdentifier
	rubyTokenConstant
	rubyTokenKeyword
	rubyTokenOperator
	rubyTokenSymbol
	rubyTokenString
	rubyTokenNumber
	rubyTokenComma
	rubyTokenDot
	rubyTokenDoubleColon
	rubyTokenSemicolon
	rubyTokenLParen
	rubyTokenRParen
	rubyTokenLBracket
	rubyTokenRBracket
	rubyTokenLBrace
	rubyTokenRBrace
)

type rubyToken struct {
	kind   rubyTokenKind
	text   string
	line   int
	column int
}

var rubyKeywords = map[string]struct{}{
	"BEGIN": {}, "END": {},
	"alias": {}, "and": {}, "begin": {}, "break": {}, "case": {}, "class": {},
	"def": {}, "defined?": {}, "do": {}, "else": {}, "elsif": {}, "end": {},
	"ensure": {}, "false": {}, "for": {}, "if": {}, "in": {}, "module": {},
	"next": {}, "nil": {}, "not": {}, "or": {}, "redo": {}, "rescue": {},
	"retry": {}, "return": {}, "self": {}, "super": {}, "then": {},
	"true": {}, "undef": {}, "unless": {}, "until": {}, "when": {}, "while": {}, "yield": {},
}

var rubyDynamicDispatchers = map[string]EdgeConfidence{
	"send":          EdgeConfidencePossible,
	"public_send":   EdgeConfidencePossible,
	"try":           EdgeConfidencePossible,
	"__send__":      EdgeConfidencePossible,
	"method":        EdgeConfidencePossible,
	"public_method": EdgeConfidencePossible,
}

var rubySymbolInvokerCalls = map[string]EdgeConfidence{
	"before_action":         EdgeConfidenceProbable,
	"after_action":          EdgeConfidenceProbable,
	"around_action":         EdgeConfidenceProbable,
	"before_filter":         EdgeConfidenceProbable,
	"after_filter":          EdgeConfidenceProbable,
	"around_filter":         EdgeConfidenceProbable,
	"helper_method":         EdgeConfidenceProbable,
	"prepend_before_action": EdgeConfidenceProbable,
	"append_before_action":  EdgeConfidenceProbable,
}

var rubyAttrAccessors = map[string]struct {
	reader bool
	writer bool
}{
	"attr_reader":   {reader: true},
	"attr_writer":   {writer: true},
	"attr_accessor": {reader: true, writer: true},
}

func lexRuby(filename string, src []byte) rubyLexResult {
	input := []rune(string(src))
	tokens := make([]rubyToken, 0, len(input)/2)
	generic := make([]Token, 0, len(input)/4)

	line, column := 1, 1
	i := 0
	for i < len(input) {
		ch := input[i]
		switch {
		case ch == '\n':
			tokens = append(tokens, rubyToken{kind: rubyTokenNewline, text: "\n", line: line, column: column})
			line++
			column = 1
			i++
		case ch == ' ' || ch == '\t' || ch == '\r' || ch == '\v' || ch == '\f':
			column++
			i++
		case ch == '#':
			for i < len(input) && input[i] != '\n' {
				i++
				column++
			}
		case ch == '\'' || ch == '"':
			startLine, startColumn := line, column
			quote := ch
			i++
			column++
			var builder strings.Builder
			for i < len(input) {
				r := input[i]
				if r == '\n' {
					line++
					column = 1
					i++
					builder.WriteRune('\n')
					continue
				}
				if r == quote {
					i++
					column++
					break
				}
				if r == '\\' && i+1 < len(input) {
					builder.WriteRune(r)
					i += 2
					column += 2
					continue
				}
				builder.WriteRune(r)
				i++
				column++
			}
			tokens = append(tokens, rubyToken{kind: rubyTokenString, text: builder.String(), line: startLine, column: startColumn})
		case ch == '<' && i+1 < len(input) && input[i+1] == '<':
			i, line, column = lexRubyHeredoc(input, i, line, column)
			tokens = append(tokens, rubyToken{kind: rubyTokenOperator, text: "<<", line: line, column: column})
		case ch == ':':
			if i+1 < len(input) && input[i+1] == ':' {
				tokens = append(tokens, rubyToken{kind: rubyTokenDoubleColon, text: "::", line: line, column: column})
				i += 2
				column += 2
				continue
			}
			startLine, startColumn := line, column
			i++
			column++
			var builder strings.Builder
			builder.WriteRune(':')
			for i < len(input) {
				r := input[i]
				if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '!' || r == '?' || r == '=' {
					builder.WriteRune(r)
					i++
					column++
					continue
				}
				break
			}
			tokens = append(tokens, rubyToken{kind: rubyTokenSymbol, text: builder.String(), line: startLine, column: startColumn})
		case ch == '(':
			tokens = append(tokens, rubyToken{kind: rubyTokenLParen, text: "(", line: line, column: column})
			i++
			column++
		case ch == ')':
			tokens = append(tokens, rubyToken{kind: rubyTokenRParen, text: ")", line: line, column: column})
			i++
			column++
		case ch == '[':
			tokens = append(tokens, rubyToken{kind: rubyTokenLBracket, text: "[", line: line, column: column})
			i++
			column++
		case ch == ']':
			tokens = append(tokens, rubyToken{kind: rubyTokenRBracket, text: "]", line: line, column: column})
			i++
			column++
		case ch == '{':
			tokens = append(tokens, rubyToken{kind: rubyTokenLBrace, text: "{", line: line, column: column})
			i++
			column++
		case ch == '}':
			tokens = append(tokens, rubyToken{kind: rubyTokenRBrace, text: "}", line: line, column: column})
			i++
			column++
		case ch == ',':
			tokens = append(tokens, rubyToken{kind: rubyTokenComma, text: ",", line: line, column: column})
			i++
			column++
		case ch == ';':
			tokens = append(tokens, rubyToken{kind: rubyTokenSemicolon, text: ";", line: line, column: column})
			i++
			column++
		default:
			if unicode.IsDigit(ch) {
				startLine, startColumn := line, column
				for i < len(input) && (unicode.IsDigit(input[i]) || input[i] == '_' || input[i] == '.') {
					i++
					column++
				}
				tokens = append(tokens, rubyToken{kind: rubyTokenNumber, text: "number", line: startLine, column: startColumn})
				continue
			}
			if isRubyIdentifierStart(ch) {
				startLine, startColumn := line, column
				var builder strings.Builder
				builder.WriteRune(ch)
				i++
				column++
				for i < len(input) {
					r := input[i]
					if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '!' || r == '?' || r == '=' {
						builder.WriteRune(r)
						i++
						column++
						continue
					}
					break
				}
				text := builder.String()
				kind := rubyTokenIdentifier
				if _, ok := rubyKeywords[text]; ok {
					kind = rubyTokenKeyword
				} else if startsWithUpper(text) {
					kind = rubyTokenConstant
				}
				tokens = append(tokens, rubyToken{kind: kind, text: text, line: startLine, column: startColumn})
				if kind == rubyTokenKeyword {
					generic = append(generic, Token{Kind: TokenKindKeyword, Text: text, Range: Span{File: filename, Start: Position{Line: startLine, Column: startColumn}, End: Position{Line: startLine, Column: startColumn + len([]rune(text))}}})
				} else if kind == rubyTokenIdentifier || kind == rubyTokenConstant {
					generic = append(generic, Token{Kind: TokenKindIdentifier, Text: text, Range: Span{File: filename, Start: Position{Line: startLine, Column: startColumn}, End: Position{Line: startLine, Column: startColumn + len([]rune(text))}}})
				}
				continue
			}
			startLine, startColumn := line, column
			op := readRubyOperator(input, &i, &column)
			tokens = append(tokens, rubyToken{kind: rubyTokenOperator, text: op, line: startLine, column: startColumn})
		}
	}
	tokens = append(tokens, rubyToken{kind: rubyTokenEOF, text: "", line: line, column: column})
	return rubyLexResult{tokens: tokens, genericTokens: generic}
}

func lexRubyHeredoc(input []rune, i int, line, column int) (int, int, int) {
	i += 2
	column += 2
	stripIndent := false
	if i < len(input) && (input[i] == '-' || input[i] == '~') {
		if input[i] == '-' {
			stripIndent = true
		}
		i++
		column++
	}
	for i < len(input) && unicode.IsSpace(input[i]) && input[i] != '\n' {
		i++
		column++
	}
	labelStart := i
	for i < len(input) && !unicode.IsSpace(input[i]) {
		i++
		column++
	}
	label := string(input[labelStart:i])
	for i < len(input) {
		if input[i] == '\n' {
			line++
			column = 1
			i++
			if label == "" {
				break
			}
			segmentStart := i
			for segmentStart < len(input) && input[segmentStart] == ' ' {
				segmentStart++
			}
			end := i
			for end < len(input) && input[end] != '\n' {
				end++
			}
			candidate := string(input[segmentStart:end])
			if candidate == label || (stripIndent && strings.TrimSpace(candidate) == label) {
				i = end
				break
			}
			continue
		}
		i++
	}
	return i, line, 1
}

func readRubyOperator(input []rune, idx *int, column *int) string {
	i := *idx
	start := i
	for i < len(input) {
		r := input[i]
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || unicode.IsSpace(r) {
			break
		}
		if r == '\n' {
			break
		}
		i++
		(*column)++
		if r == '.' && i < len(input) && input[i] == '.' {
			continue
		}
	}
	*idx = i
	return string(input[start:i])
}

func isRubyIdentifierStart(r rune) bool {
	return unicode.IsLetter(r) || r == '_' || r == '$' || r == '@'
}

func startsWithUpper(s string) bool {
	if s == "" {
		return false
	}
	r, _ := utf8.DecodeRuneInString(s)
	return unicode.IsUpper(r)
}

func parseRubyFile(filename string, lex rubyLexResult) *rubyUnit {
	parser := newRubyParser(filename, lex.tokens)
	parser.parse()
	parser.file.methods = append(parser.file.methods, parser.generatedMethods...)
	return parser.file
}

type rubyParser struct {
	filename         string
	tokens           []rubyToken
	pos              int
	file             *rubyUnit
	scopeParts       []string
	methodDefaults   []rubyMethodType
	visibility       []rubyVisibility
	moduleFunc       []bool
	blockStack       []rubyBlock
	methodStack      []*rubyMethodContext
	pendingDynamic   []*pendingDynamicMethod
	generatedMethods []*rubyMethod
	dslRules         []DSLRule
}

type rubyBlockKind int

const (
	rubyBlockClass rubyBlockKind = iota
	rubyBlockModule
	rubyBlockSingleton
	rubyBlockMethod
	rubyBlockGeneric
)

type rubyBlock struct {
	kind         rubyBlockKind
	elements     int
	prevDefault  rubyMethodType
	prevVis      rubyVisibility
	prevModuleFn bool
	method       *rubyMethodContext
	brace        bool
}

type rubyMethodContext struct {
	method    *rubyMethod
	callsSeen map[string]struct{}
}

type pendingDynamicMethod struct {
	method      *rubyMethod
	expectBlock bool
}

func newRubyParser(filename string, tokens []rubyToken) *rubyParser {
	return &rubyParser{
		filename:       filename,
		tokens:         tokens,
		file:           &rubyUnit{types: make(map[string]*rubyType)},
		scopeParts:     []string{},
		methodDefaults: []rubyMethodType{rubyMethodTopLevel},
		visibility:     []rubyVisibility{rubyVisibilityPublic},
		moduleFunc:     []bool{false},
		dslRules:       GlobalDSLRegistry().RulesFor("ruby"),
	}
}

func (p *rubyParser) parse() {
	for !p.isEOF() {
		tok := p.peek()
		switch tok.kind {
		case rubyTokenKeyword:
			switch tok.text {
			case "class":
				p.parseClass()
				continue
			case "module":
				p.parseModule()
				continue
			case "def":
				p.parseDef()
				continue
			case "end":
				p.advance()
				p.popBlock()
				continue
			case "do":
				if p.activatePendingDynamic(false) {
					p.advance()
					continue
				}
				p.advance()
				p.pushGenericBlock(false)
				continue
			case "begin", "case", "for", "while", "until", "loop", "if", "unless":
				p.advance()
				p.pushGenericBlock(false)
				continue
			case "include":
				p.advance()
				p.parseInclude()
				continue
			case "extend":
				p.advance()
				p.parseExtend()
				continue
			case "prepend":
				p.advance()
				p.parsePrepend()
				continue
			case "alias":
				p.advance()
				p.parseAlias()
				continue
			case "require", "require_relative", "load":
				p.advance()
				p.parseRequire(tok.text)
				continue
			case "private", "protected", "public":
				p.advance()
				p.parseVisibilityDirective(tok.text)
				continue
			case "module_function":
				p.advance()
				p.parseModuleFunction()
				continue
			case "self":
				p.recordCalls(tok)
			}
		case rubyTokenIdentifier:
			if len(p.methodStack) == 0 {
				if p.handleTopLevelIdentifier(tok) {
					p.advance()
					continue
				}
			}
			p.recordCalls(tok)
		case rubyTokenConstant, rubyTokenOperator, rubyTokenSymbol, rubyTokenNumber, rubyTokenDoubleColon:
			p.recordCalls(tok)
		case rubyTokenLBrace:
			if p.activatePendingDynamic(true) {
				p.advance()
				continue
			}
		case rubyTokenRBrace:
			p.advance()
			p.popBrace()
			continue
		}
		p.advance()
	}

	for _, pending := range p.pendingDynamic {
		if pending.method != nil {
			p.file.methods = append(p.file.methods, pending.method)
		}
	}
}

func (p *rubyParser) parseClass() {
	classTok := p.advance()
	if p.matchOperator("<<") {
		if p.peek().kind == rubyTokenKeyword && p.peek().text == "self" {
			p.advance()
		}
		prevDefault := p.currentDefault()
		prevVis := p.currentVisibility()
		prevMF := p.moduleFunc[len(p.moduleFunc)-1]
		p.methodDefaults = append(p.methodDefaults, rubyMethodClass)
		p.visibility = append(p.visibility, prevVis)
		p.moduleFunc = append(p.moduleFunc, prevMF)
		p.blockStack = append(p.blockStack, rubyBlock{kind: rubyBlockSingleton, prevDefault: prevDefault, prevVis: prevVis, prevModuleFn: prevMF})
		return
	}
	name, components := p.parseQualifiedName()
	if components == 0 {
		name = "AnonymousClass"
		components = 1
	}
	super := ""
	if p.matchOperator("<") {
		super, _ = p.parseQualifiedName()
	}
	for _, part := range strings.Split(name, "::") {
		if part == "" {
			continue
		}
		p.scopeParts = append(p.scopeParts, part)
	}
	typeInfo := p.ensureType(p.currentReceiver())
	typeInfo.Kind = rubyTypeClass
	if super != "" {
		typeInfo.Super = super
	}
	p.methodDefaults = append(p.methodDefaults, rubyMethodInstance)
	p.visibility = append(p.visibility, rubyVisibilityPublic)
	p.moduleFunc = append(p.moduleFunc, false)
	p.blockStack = append(p.blockStack, rubyBlock{kind: rubyBlockClass, elements: components})
	_ = classTok
}

func (p *rubyParser) parseModule() {
	moduleTok := p.advance()
	name, components := p.parseQualifiedName()
	if components == 0 {
		name = "AnonymousModule"
		components = 1
	}
	for _, part := range strings.Split(name, "::") {
		if part == "" {
			continue
		}
		p.scopeParts = append(p.scopeParts, part)
	}
	typeInfo := p.ensureType(p.currentReceiver())
	typeInfo.Kind = rubyTypeModule
	p.methodDefaults = append(p.methodDefaults, rubyMethodInstance)
	p.visibility = append(p.visibility, rubyVisibilityPublic)
	p.moduleFunc = append(p.moduleFunc, false)
	p.blockStack = append(p.blockStack, rubyBlock{kind: rubyBlockModule, elements: components})
	_ = moduleTok
}

func (p *rubyParser) parseDef() {
	defTok := p.advance()
	receiver, name, methodType := p.parseMethodTarget()
	if name == "" {
		return
	}
	method := &rubyMethod{
		name:       name,
		receiver:   receiverOrDefault(receiver),
		typ:        methodType,
		location:   Location{File: p.filename, Line: defTok.line, Column: defTok.column},
		attributes: make(map[string]any),
	}
	method.attributes["visibility"] = string(p.currentVisibility())
	if p.moduleFunc[len(p.moduleFunc)-1] {
		method.attributes["module_function"] = true
	}
	if method.typ == rubyMethodTopLevel && method.name == "main" {
		method.attributes["entrypoint"] = true
	}
	params, blockParam := p.parseMethodParams()
	method.params = params
	if blockParam != "" {
		method.blockParam = blockParam
		method.hasBlock = true
	}
	p.applyMethodRules(method)
	ctx := &rubyMethodContext{method: method}
	p.methodStack = append(p.methodStack, ctx)
	p.blockStack = append(p.blockStack, rubyBlock{kind: rubyBlockMethod, method: ctx})
}

func (p *rubyParser) parseDynamicMethod(kind string) {
	name, line, column, ok := p.readDynamicMethodName()
	if !ok || name == "" {
		return
	}
	methodType := p.currentDefault()
	if kind == "define_singleton_method" {
		methodType = rubyMethodClass
	}
	method := &rubyMethod{
		name:       name,
		receiver:   receiverOrDefault(p.currentReceiver()),
		typ:        methodType,
		location:   Location{File: p.filename, Line: line, Column: column},
		attributes: map[string]any{"dynamic_definition": kind, "visibility": string(p.currentVisibility())},
	}
	p.applyMethodRules(method)
	p.pendingDynamic = append(p.pendingDynamic, &pendingDynamicMethod{method: method, expectBlock: true})
}

func (p *rubyParser) activatePendingDynamic(usesBrace bool) bool {
	if len(p.pendingDynamic) == 0 {
		return false
	}
	pending := p.pendingDynamic[len(p.pendingDynamic)-1]
	if !pending.expectBlock {
		return false
	}
	p.pendingDynamic = p.pendingDynamic[:len(p.pendingDynamic)-1]
	ctx := &rubyMethodContext{method: pending.method}
	p.methodStack = append(p.methodStack, ctx)
	p.blockStack = append(p.blockStack, rubyBlock{kind: rubyBlockMethod, method: ctx, brace: usesBrace})
	return true
}

func (p *rubyParser) parseQualifiedName() (string, int) {
	var parts []string
	components := 0
	for {
		tok := p.peek()
		if tok.kind != rubyTokenIdentifier && tok.kind != rubyTokenConstant {
			break
		}
		parts = append(parts, tok.text)
		components++
		p.advance()
		if p.matchDoubleColon() {
			continue
		}
		break
	}
	return strings.Join(parts, "::"), components
}

func (p *rubyParser) parseMethodTarget() (string, string, rubyMethodType) {
	receiver := p.currentReceiver()
	defaultType := p.currentDefault()
	methodType := defaultType

	if p.peek().kind == rubyTokenKeyword && p.peek().text == "self" {
		p.advance()
		if p.matchOperator(".") || p.matchDoubleColon() {
			name, _, ok := p.extractMethodNameWithIndex(p.pos)
			if !ok {
				return receiver, "", methodType
			}
			methodType = rubyMethodClass
			return receiver, name, methodType
		}
		return receiver, "", methodType
	}

	saved := p.pos
	receiverParts := []string{}
	for {
		tok := p.peek()
		if tok.kind != rubyTokenIdentifier && tok.kind != rubyTokenConstant {
			break
		}
		receiverParts = append(receiverParts, tok.text)
		p.advance()
		if p.matchOperator(".") {
			name, _, ok := p.extractMethodNameWithIndex(p.pos)
			if !ok {
				p.pos = saved
				return receiver, "", methodType
			}
			resolved := strings.Join(receiverParts, "::")
			if resolved == "" {
				resolved = receiver
			}
			methodType = rubyMethodClass
			return resolved, name, methodType
		}
		if p.matchDoubleColon() {
			continue
		}
		break
	}
	p.pos = saved

	name, _, ok := p.extractMethodNameWithIndex(p.pos)
	if !ok {
		return receiver, "", methodType
	}
	if defaultType == rubyMethodTopLevel {
		receiver = "Object"
	}
	return receiver, name, methodType
}

func (p *rubyParser) parseMethodParams() ([]rubyParam, string) {
	start := p.nextNonNewline(p.pos)
	if start < 0 {
		return nil, ""
	}
	tokens := p.tokens
	params := []rubyParam{}
	blockParam := ""
	idx := start

	parseParam := func(kind rubyParamKind, tok rubyToken) {
		name := tok.text
		params = append(params, rubyParam{name: name, kind: kind})
	}

	skipDefault := func(i int) int {
		depth := 0
		for i < len(tokens) {
			t := tokens[i]
			if depth == 0 && (t.kind == rubyTokenComma || t.kind == rubyTokenNewline || t.kind == rubyTokenSemicolon || t.kind == rubyTokenRParen) {
				break
			}
			if t.kind == rubyTokenLParen {
				depth++
			} else if t.kind == rubyTokenRParen {
				if depth == 0 {
					break
				}
				depth--
			}
			i++
		}
		return i
	}

	if tokens[idx].kind == rubyTokenLParen {
		idx++
		for idx < len(tokens) {
			tok := tokens[idx]
			if tok.kind == rubyTokenRParen {
				idx++
				break
			}
			if tok.kind == rubyTokenComma {
				idx++
				continue
			}
			kind := rubyParamNormal
			if tok.kind == rubyTokenOperator {
				switch tok.text {
				case "*":
					kind = rubyParamRest
					idx++
					tok = tokens[idx]
				case "**":
					kind = rubyParamKeyRest
					idx++
					tok = tokens[idx]
				case "&":
					kind = rubyParamBlock
					idx++
					tok = tokens[idx]
				}
			}
			if tok.kind == rubyTokenIdentifier || tok.kind == rubyTokenConstant {
				if kind == rubyParamBlock {
					blockParam = tok.text
				} else {
					parseParam(kind, tok)
				}
				idx++
				idx = skipDefault(idx)
				continue
			}
			idx++
		}
		p.pos = idx
		return params, blockParam
	}

	// No parentheses, parse until newline or terminator
	idx = start
	for idx < len(tokens) {
		tok := tokens[idx]
		if tok.kind == rubyTokenNewline || tok.kind == rubyTokenSemicolon {
			break
		}
		if tok.kind == rubyTokenKeyword {
			break
		}
		if tok.kind == rubyTokenComma {
			idx++
			continue
		}
		kind := rubyParamNormal
		if tok.kind == rubyTokenOperator {
			switch tok.text {
			case "*":
				kind = rubyParamRest
				idx++
				tok = tokens[idx]
			case "**":
				kind = rubyParamKeyRest
				idx++
				tok = tokens[idx]
			case "&":
				kind = rubyParamBlock
				idx++
				tok = tokens[idx]
			}
		}
		if tok.kind == rubyTokenIdentifier || tok.kind == rubyTokenConstant {
			if kind == rubyParamBlock {
				blockParam = tok.text
			} else {
				parseParam(kind, tok)
			}
			idx++
			idx = skipDefault(idx)
			continue
		}
		idx++
	}
	p.pos = idx
	return params, blockParam
}

func (p *rubyParser) extractMethodNameWithIndex(idx int) (string, int, bool) {
	i := p.nextNonNewline(idx)
	if i < 0 {
		return "", -1, false
	}
	tok := p.tokens[i]
	switch tok.kind {
	case rubyTokenIdentifier, rubyTokenConstant:
		return tok.text, i, true
	case rubyTokenOperator:
		return tok.text, i, true
	case rubyTokenLBracket:
		j := p.nextNonNewline(i + 1)
		if j >= 0 && p.tokens[j].kind == rubyTokenRBracket {
			k := p.nextNonNewline(j + 1)
			if k >= 0 && p.tokens[k].kind == rubyTokenOperator && p.tokens[k].text == "=" {
				return "[]=", k, true
			}
			return "[]", j, true
		}
	}
	return "", -1, false
}

func (p *rubyParser) readDynamicMethodName() (string, int, int, bool) {
	i := p.pos + 1
	parenDepth := 0
	for i < len(p.tokens) {
		tok := p.tokens[i]
		switch tok.kind {
		case rubyTokenLParen:
			parenDepth++
		case rubyTokenRParen:
			if parenDepth == 0 {
				return "", 0, 0, false
			}
			parenDepth--
		case rubyTokenNewline:
			i++
			continue
		case rubyTokenSymbol:
			return strings.TrimPrefix(tok.text, ":"), tok.line, tok.column, true
		case rubyTokenString, rubyTokenIdentifier:
			return tok.text, tok.line, tok.column, true
		}
		i++
	}
	return "", 0, 0, false
}

func (p *rubyParser) handleTopLevelIdentifier(tok rubyToken) bool {
	if accessor, ok := rubyAttrAccessors[tok.text]; ok {
		symbols := p.collectSymbolArgs(p.pos + 1)
		if len(symbols) == 0 {
			return false
		}
		p.generateAttrMethods(tok, accessor, symbols)
		return true
	}
	if conf, ok := rubySymbolInvokerCalls[tok.text]; ok {
		symbols := p.collectSymbolArgs(p.pos + 1)
		if len(symbols) == 0 {
			return false
		}
		typeInfo := p.ensureType(p.currentReceiver())
		if typeInfo.Visibility == nil {
			typeInfo.Visibility = make(map[string]rubyVisibility)
		}
		_ = conf
		return true
	}
	if tok.text == "define_method" || tok.text == "define_singleton_method" {
		p.parseDynamicMethod(tok.text)
		return true
	}
	return false
}

func (p *rubyParser) generateAttrMethods(tok rubyToken, accessor struct{ reader, writer bool }, symbols []string) {
	typeName := receiverOrDefault(p.currentReceiver())
	for _, name := range symbols {
		if accessor.reader {
			method := &rubyMethod{
				name:       name,
				receiver:   typeName,
				typ:        rubyMethodInstance,
				location:   Location{File: p.filename, Line: tok.line, Column: tok.column},
				attributes: map[string]any{"generated": tok.text, "visibility": string(p.currentVisibility())},
			}
			p.applyMethodRules(method)
			p.generatedMethods = append(p.generatedMethods, method)
		}
		if accessor.writer {
			method := &rubyMethod{
				name:       name + "=",
				receiver:   typeName,
				typ:        rubyMethodInstance,
				location:   Location{File: p.filename, Line: tok.line, Column: tok.column},
				attributes: map[string]any{"generated": tok.text, "visibility": string(p.currentVisibility())},
			}
			p.applyMethodRules(method)
			p.generatedMethods = append(p.generatedMethods, method)
		}
	}
}

func (p *rubyParser) parseInclude() {
	targets := p.collectNameList(p.pos)
	if len(targets) == 0 {
		return
	}
	typeInfo := p.ensureType(p.currentReceiver())
	typeInfo.Includes = appendUnique(typeInfo.Includes, targets...)
}

func (p *rubyParser) parseExtend() {
	targets := p.collectNameList(p.pos)
	if len(targets) == 0 {
		return
	}
	typeInfo := p.ensureType(p.currentReceiver())
	typeInfo.Extends = appendUnique(typeInfo.Extends, targets...)
}

func (p *rubyParser) parsePrepend() {
	targets := p.collectNameList(p.pos)
	if len(targets) == 0 {
		return
	}
	typeInfo := p.ensureType(p.currentReceiver())
	typeInfo.Prepends = appendUnique(typeInfo.Prepends, targets...)
}

func (p *rubyParser) parseAlias() {
	newName, ok := p.parseAliasName()
	if !ok {
		return
	}
	oldName, ok := p.parseAliasName()
	if !ok {
		return
	}
	alias := rubyAlias{owner: receiverOrDefault(p.currentReceiver()), new: newName, old: oldName, typ: p.currentDefault()}
	p.file.aliases = append(p.file.aliases, alias)
}

func (p *rubyParser) parseAliasName() (string, bool) {
	tok := p.nextSignificant()
	if tok.kind == rubyTokenSymbol {
		return strings.TrimPrefix(tok.text, ":"), true
	}
	if tok.kind == rubyTokenIdentifier || tok.kind == rubyTokenConstant {
		return tok.text, true
	}
	return "", false
}

func (p *rubyParser) parseRequire(kind string) {
	tok := p.nextSignificant()
	if tok.kind != rubyTokenString {
		return
	}
	p.file.requires = append(p.file.requires, rubyRequire{path: tok.text, kind: kind})
}

func (p *rubyParser) parseVisibilityDirective(kind string) {
	symbols := p.collectSymbolArgs(p.pos)
	if len(symbols) == 0 {
		switch kind {
		case "private":
			p.visibility[len(p.visibility)-1] = rubyVisibilityPrivate
		case "protected":
			p.visibility[len(p.visibility)-1] = rubyVisibilityProtected
		case "public":
			p.visibility[len(p.visibility)-1] = rubyVisibilityPublic
		}
		return
	}
	typeInfo := p.ensureType(p.currentReceiver())
	if typeInfo.Visibility == nil {
		typeInfo.Visibility = make(map[string]rubyVisibility)
	}
	vis := rubyVisibilityPublic
	switch kind {
	case "private":
		vis = rubyVisibilityPrivate
	case "protected":
		vis = rubyVisibilityProtected
	default:
		vis = rubyVisibilityPublic
	}
	for _, name := range symbols {
		typeInfo.Visibility[name] = vis
	}
}

func (p *rubyParser) parseModuleFunction() {
	symbols := p.collectSymbolArgs(p.pos)
	typeInfo := p.ensureType(p.currentReceiver())
	if typeInfo.ModuleFunctions == nil {
		typeInfo.ModuleFunctions = make(map[string]struct{})
	}
	if len(symbols) == 0 {
		p.moduleFunc[len(p.moduleFunc)-1] = true
		typeInfo.ModuleFnDefault = true
		return
	}
	for _, name := range symbols {
		typeInfo.ModuleFunctions[name] = struct{}{}
	}
}

func (p *rubyParser) collectSymbolArgs(start int) []string {
	idx := p.nextNonNewline(start)
	if idx < 0 {
		return nil
	}
	tokens := p.tokens
	result := []string{}
	if tokens[idx].kind == rubyTokenLParen {
		idx++
		depth := 1
		for idx < len(tokens) && depth > 0 {
			tok := tokens[idx]
			if tok.kind == rubyTokenLParen {
				depth++
			} else if tok.kind == rubyTokenRParen {
				depth--
			} else if depth == 1 && tok.kind == rubyTokenSymbol {
				result = append(result, strings.TrimPrefix(tok.text, ":"))
			} else if depth == 1 && tok.kind == rubyTokenString {
				result = append(result, tok.text)
			}
			idx++
		}
		return result
	}
	for idx < len(tokens) {
		tok := tokens[idx]
		if tok.kind == rubyTokenSymbol {
			result = append(result, strings.TrimPrefix(tok.text, ":"))
		} else if tok.kind == rubyTokenString {
			result = append(result, tok.text)
		} else {
			break
		}
		next := p.nextNonNewline(idx + 1)
		if next < 0 || tokens[next].kind != rubyTokenComma {
			break
		}
		idx = p.nextNonNewline(next + 1)
	}
	return result
}

func (p *rubyParser) collectNameList(start int) []string {
	idx := p.nextNonNewline(start)
	if idx < 0 {
		return nil
	}
	tokens := p.tokens
	result := []string{}
	if tokens[idx].kind == rubyTokenLParen {
		idx++
		depth := 1
		for idx < len(tokens) && depth > 0 {
			tok := tokens[idx]
			if tok.kind == rubyTokenLParen {
				depth++
			} else if tok.kind == rubyTokenRParen {
				depth--
			} else if depth == 1 && (tok.kind == rubyTokenIdentifier || tok.kind == rubyTokenConstant) {
				name, _ := p.parseQualifiedNameAt(idx)
				if name != "" {
					result = append(result, name)
				}
			}
			idx++
		}
		return result
	}
	for idx < len(tokens) {
		name, consumed := p.parseQualifiedNameAt(idx)
		if name == "" {
			break
		}
		result = append(result, name)
		idx = consumed
		next := p.nextNonNewline(idx)
		if next < 0 || tokens[next].kind != rubyTokenComma {
			break
		}
		idx = next + 1
	}
	return result
}

func (p *rubyParser) parseQualifiedNameAt(idx int) (string, int) {
	var parts []string
	i := idx
	for i < len(p.tokens) {
		tok := p.tokens[i]
		if tok.kind != rubyTokenIdentifier && tok.kind != rubyTokenConstant {
			break
		}
		parts = append(parts, tok.text)
		i++
		if i < len(p.tokens) && p.tokens[i].kind == rubyTokenDoubleColon {
			i++
			continue
		}
		break
	}
	if len(parts) == 0 {
		return "", idx
	}
	return strings.Join(parts, "::"), i
}

func appendUnique(dst []string, vals ...string) []string {
	index := make(map[string]struct{}, len(dst))
	for _, v := range dst {
		index[v] = struct{}{}
	}
	for _, v := range vals {
		if _, ok := index[v]; ok {
			continue
		}
		index[v] = struct{}{}
		dst = append(dst, v)
	}
	return dst
}

func (p *rubyParser) ensureType(name string) *rubyType {
	if name == "" {
		name = "Object"
	}
	typ, ok := p.file.types[name]
	if !ok {
		typ = &rubyType{Name: name}
		p.file.types[name] = typ
	}
	return typ
}

func (p *rubyParser) pushGenericBlock(brace bool) {
	p.blockStack = append(p.blockStack, rubyBlock{kind: rubyBlockGeneric, brace: brace})
}

func (p *rubyParser) popBrace() {
	if len(p.blockStack) == 0 {
		return
	}
	frame := p.blockStack[len(p.blockStack)-1]
	if !frame.brace {
		return
	}
	p.popBlock()
}

func (p *rubyParser) popBlock() {
	if len(p.blockStack) == 0 {
		if len(p.methodStack) > 0 {
			ctx := p.methodStack[len(p.methodStack)-1]
			p.methodStack = p.methodStack[:len(p.methodStack)-1]
			p.file.methods = append(p.file.methods, ctx.method)
		}
		return
	}
	frame := p.blockStack[len(p.blockStack)-1]
	p.blockStack = p.blockStack[:len(p.blockStack)-1]
	switch frame.kind {
	case rubyBlockClass, rubyBlockModule:
		if frame.elements > 0 && len(p.scopeParts) >= frame.elements {
			p.scopeParts = p.scopeParts[:len(p.scopeParts)-frame.elements]
		} else {
			p.scopeParts = nil
		}
		if len(p.methodDefaults) > 1 {
			p.methodDefaults = p.methodDefaults[:len(p.methodDefaults)-1]
		}
		if len(p.visibility) > 1 {
			p.visibility = p.visibility[:len(p.visibility)-1]
		}
		if len(p.moduleFunc) > 1 {
			p.moduleFunc = p.moduleFunc[:len(p.moduleFunc)-1]
		}
	case rubyBlockSingleton:
		if len(p.methodDefaults) > 1 {
			p.methodDefaults = p.methodDefaults[:len(p.methodDefaults)-1]
		}
		if len(p.visibility) > 0 {
			p.visibility[len(p.visibility)-1] = frame.prevVis
		}
		if len(p.moduleFunc) > 0 {
			p.moduleFunc[len(p.moduleFunc)-1] = frame.prevModuleFn
		}
	case rubyBlockMethod:
		if len(p.methodStack) > 0 {
			ctx := p.methodStack[len(p.methodStack)-1]
			p.methodStack = p.methodStack[:len(p.methodStack)-1]
			p.file.methods = append(p.file.methods, ctx.method)
		}
	case rubyBlockGeneric:
		// no-op
	}
}

func (p *rubyParser) recordCalls(tok rubyToken) {
	if len(p.methodStack) == 0 {
		return
	}
	switch tok.kind {
	case rubyTokenOperator:
		if tok.text == "." || tok.text == "&." {
			p.recordExplicitCall(tok.text)
		}
	case rubyTokenDoubleColon:
		p.recordExplicitScopedCall()
	case rubyTokenIdentifier:
		p.recordBareCall(tok)
	}
}

func (p *rubyParser) recordExplicitCall(op string) {
	ctx := p.methodStack[len(p.methodStack)-1]
	receiver, ok := p.extractReceiver(p.pos - 1)
	if !ok {
		return
	}
	name, nameIdx, ok := p.extractMethodNameWithIndex(p.pos + 1)
	if !ok {
		return
	}
	call := rubyCall{
		name:       name,
		receiver:   receiverOrDefault(receiver),
		typ:        p.resolveCallType(receiver, op),
		confidence: EdgeConfidenceCertain,
		source:     "direct",
	}
	symbols := p.collectSymbolArgs(nameIdx + 1)
	call.symbolArgs = symbols
	info := p.collectCallArgumentInfo(nameIdx+1, ctx.method)
	call.argCount = info.count
	call.hasBlock = info.hasBlock
	call.argDescriptors = info.args
	call.blockParams = info.blockParams
	call.location = tokenLocation(p.tokens[nameIdx], p.filename)
	p.applyCallRules(&call, ctx.method)
	ctx.addCall(call)
	p.expandSymbolDispatch(ctx, call, symbols)
}

func (p *rubyParser) recordExplicitScopedCall() {
	ctx := p.methodStack[len(p.methodStack)-1]
	receiver, ok := p.extractReceiver(p.pos - 1)
	if !ok {
		return
	}
	name, nameIdx, ok := p.extractMethodNameWithIndex(p.pos + 1)
	if !ok {
		return
	}
	call := rubyCall{
		name:       name,
		receiver:   receiverOrDefault(receiver),
		typ:        rubyMethodClass,
		confidence: EdgeConfidenceCertain,
		source:     "direct",
	}
	symbols := p.collectSymbolArgs(nameIdx + 1)
	call.symbolArgs = symbols
	info := p.collectCallArgumentInfo(nameIdx+1, ctx.method)
	call.argCount = info.count
	call.hasBlock = info.hasBlock
	call.argDescriptors = info.args
	call.blockParams = info.blockParams
	call.location = tokenLocation(p.tokens[nameIdx], p.filename)
	p.applyCallRules(&call, ctx.method)
	ctx.addCall(call)
	p.expandSymbolDispatch(ctx, call, symbols)
}

func (p *rubyParser) recordBareCall(tok rubyToken) {
	if _, ok := rubyKeywords[tok.text]; ok {
		return
	}
	if tok.text == "yield" {
		ctx := p.methodStack[len(p.methodStack)-1]
		info := p.collectCallArgumentInfo(p.pos+1, ctx.method)
		call := rubyCall{
			name:           "<yield>",
			receiver:       receiverOrDefault(p.currentReceiver()),
			typ:            p.currentDefault(),
			confidence:     EdgeConfidenceCertain,
			source:         "yield",
			argCount:       info.count,
			hasBlock:       info.hasBlock,
			yieldCall:      true,
			argDescriptors: info.args,
			blockParams:    info.blockParams,
			location:       tokenLocation(tok, p.filename),
		}
		p.applyCallRules(&call, ctx.method)
		ctx.addCall(call)
		ctx.method.yields = true
		ctx.method.hasBlock = true
		return
	}
	if tok.text == "return" || tok.text == "super" || tok.text == "__callee__" {
		return
	}
	prev := p.previousNonNewline(p.pos - 1)
	if prev >= 0 {
		ptok := p.tokens[prev]
		if ptok.kind == rubyTokenOperator {
			if ptok.text == "." || ptok.text == "&." {
				return
			}
		}
		if ptok.kind == rubyTokenDoubleColon {
			return
		}
		if ptok.kind == rubyTokenIdentifier && strings.HasPrefix(ptok.text, "@") {
			return
		}
		if ptok.kind == rubyTokenSymbol {
			return
		}
	}
	next := p.nextNonNewline(p.pos + 1)
	if next >= 0 {
		ntok := p.tokens[next]
		if ntok.kind == rubyTokenOperator {
			if ntok.text == "=" && !(p.nextNonNewline(next+1) >= 0 && p.tokens[p.nextNonNewline(next+1)].text == "=") {
				return
			}
			if ntok.text == "=>" {
				return
			}
		}
	}
	ctx := p.methodStack[len(p.methodStack)-1]
	call := rubyCall{
		name:       tok.text,
		receiver:   receiverOrDefault(p.currentReceiver()),
		typ:        p.currentDefault(),
		confidence: EdgeConfidenceCertain,
		source:     "direct",
	}
	info := p.collectCallArgumentInfo(p.pos+1, ctx.method)
	call.argCount = info.count
	call.hasBlock = info.hasBlock
	call.argDescriptors = info.args
	call.blockParams = info.blockParams
	call.location = tokenLocation(tok, p.filename)
	symbols := p.collectSymbolArgs(p.pos + 1)
	call.symbolArgs = symbols
	p.applyCallRules(&call, ctx.method)
	ctx.addCall(call)
	p.expandSymbolDispatch(ctx, call, symbols)
}

func (p *rubyParser) expandSymbolDispatch(ctx *rubyMethodContext, call rubyCall, symbols []string) {
	if conf, ok := rubyDynamicDispatchers[call.name]; ok {
		if len(symbols) == 0 {
			newCall := rubyCall{
				name:           "method_missing",
				receiver:       call.receiver,
				typ:            call.typ,
				confidence:     EdgeConfidencePossible,
				source:         call.name,
				dynamic:        true,
				argCount:       call.argCount,
				argDescriptors: call.argDescriptors,
				blockParams:    call.blockParams,
				location:       call.location,
			}
			p.applyCallRules(&newCall, ctx.method)
			ctx.addCall(newCall)
			return
		}
		for _, sym := range symbols {
			newCall := rubyCall{
				name:           sym,
				receiver:       call.receiver,
				typ:            call.typ,
				confidence:     conf,
				source:         call.name,
				dynamic:        true,
				metadata:       map[string]any{"dispatcher": call.name},
				argCount:       call.argCount,
				argDescriptors: call.argDescriptors,
				blockParams:    call.blockParams,
				location:       call.location,
			}
			p.applyCallRules(&newCall, ctx.method)
			ctx.addCall(newCall)
		}
	}
	if conf, ok := rubySymbolInvokerCalls[call.name]; ok {
		for _, sym := range symbols {
			newCall := rubyCall{
				name:           sym,
				receiver:       call.receiver,
				typ:            call.typ,
				confidence:     conf,
				source:         call.name,
				dynamic:        true,
				argCount:       call.argCount,
				argDescriptors: call.argDescriptors,
				blockParams:    call.blockParams,
				location:       call.location,
			}
			p.applyCallRules(&newCall, ctx.method)
			ctx.addCall(newCall)
		}
	}
}

func (ctx *rubyMethodContext) addCall(call rubyCall) {
	if ctx.callsSeen == nil {
		ctx.callsSeen = make(map[string]struct{})
	}
	key := callKey(call)
	if _, ok := ctx.callsSeen[key]; ok {
		return
	}
	ctx.callsSeen[key] = struct{}{}
	ctx.method.calls = append(ctx.method.calls, call)
}

func callKey(call rubyCall) string {
	return fmt.Sprintf("%s|%s|%s|%s|%t|%t|%d|%d", call.receiver, call.name, callLocationKey(call), string(call.confidence), call.hasBlock, call.yieldCall, call.argCount, len(call.argDescriptors))
}

func fmtBool(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func callLocationKey(call rubyCall) string {
	if call.location.Line == 0 {
		return ""
	}
	return fmt.Sprintf("L%dC%d", call.location.Line, call.location.Column)
}

func (p *rubyParser) resolveCallType(receiver, op string) rubyMethodType {
	if op == "::" {
		return rubyMethodClass
	}
	if receiver == p.currentReceiver() && p.currentDefault() == rubyMethodClass {
		return rubyMethodClass
	}
	if startsWithUpper(receiver) {
		return rubyMethodClass
	}
	return rubyMethodInstance
}

func (p *rubyParser) collectCallArgumentInfo(start int, method *rubyMethod) callArgumentInfo {
	info := callArgumentInfo{}
	idx := p.nextNonNewline(start)
	if idx < 0 {
		return info
	}
	var nextIdx int
	if p.tokens[idx].kind == rubyTokenLParen {
		info.args, nextIdx = p.readArgumentsWithParens(idx, method)
	} else {
		info.args, nextIdx = p.readArgumentsNoParens(idx, method)
	}
	info.count = len(info.args)
	if params, hasBlock, _ := p.readBlockParams(nextIdx); hasBlock {
		info.blockParams = params
		info.hasBlock = true
	}
	return info
}

func (p *rubyParser) readArgumentsWithParens(start int, method *rubyMethod) ([]rubyArg, int) {
	tokens := p.tokens
	i := start + 1
	depth := 1
	current := []rubyToken{}
	args := []rubyArg{}
	for i < len(tokens) {
		tok := tokens[i]
		if tok.kind == rubyTokenLParen {
			depth++
			current = append(current, tok)
			i++
			continue
		}
		if tok.kind == rubyTokenRParen {
			depth--
			if depth == 0 {
				if arg := p.classifyArgumentTokens(current, method); arg.kind != rubyArgUnknown {
					args = append(args, arg)
				}
				i++
				break
			}
			current = append(current, tok)
			i++
			continue
		}
		if depth == 1 && tok.kind == rubyTokenComma {
			if arg := p.classifyArgumentTokens(current, method); arg.kind != rubyArgUnknown {
				args = append(args, arg)
			}
			current = nil
			i++
			continue
		}
		current = append(current, tok)
		i++
	}
	return args, i
}

func (p *rubyParser) readArgumentsNoParens(start int, method *rubyMethod) ([]rubyArg, int) {
	tokens := p.tokens
	i := start
	current := []rubyToken{}
	args := []rubyArg{}
	for i < len(tokens) {
		tok := tokens[i]
		if tok.kind == rubyTokenKeyword {
			if tok.text == "do" {
				break
			}
			break
		}
		if tok.kind == rubyTokenNewline || tok.kind == rubyTokenSemicolon {
			break
		}
		if tok.kind == rubyTokenComma {
			if arg := p.classifyArgumentTokens(current, method); arg.kind != rubyArgUnknown {
				args = append(args, arg)
			}
			current = nil
			i++
			continue
		}
		if tok.kind == rubyTokenLBrace {
			break
		}
		current = append(current, tok)
		i++
	}
	if arg := p.classifyArgumentTokens(current, method); arg.kind != rubyArgUnknown {
		args = append(args, arg)
	}
	return args, i
}

func (p *rubyParser) readBlockParams(start int) ([]string, bool, int) {
	idx := p.nextNonNewline(start)
	if idx < 0 {
		return nil, false, start
	}
	tokens := p.tokens
	tok := tokens[idx]
	switch {
	case tok.kind == rubyTokenKeyword && tok.text == "do":
		params, next := p.consumeBlockParamList(idx + 1)
		return params, true, next
	case tok.kind == rubyTokenLBrace:
		params, next := p.consumeBlockParamList(idx + 1)
		if len(params) == 0 {
			return nil, false, start
		}
		return params, true, next
	}
	return nil, false, start
}

func (p *rubyParser) consumeBlockParamList(start int) ([]string, int) {
	tokens := p.tokens
	i := p.nextNonNewline(start)
	params := []string{}
	if i >= len(tokens) {
		return params, start
	}
	if tokens[i].kind != rubyTokenOperator || tokens[i].text != "|" {
		return params, start
	}
	i++
	for i < len(tokens) {
		tok := tokens[i]
		if tok.kind == rubyTokenOperator && tok.text == "|" {
			i++
			break
		}
		if tok.kind == rubyTokenIdentifier || tok.kind == rubyTokenConstant {
			params = append(params, tok.text)
		}
		i++
	}
	return params, i
}

func (p *rubyParser) classifyArgumentTokens(tokens []rubyToken, method *rubyMethod) rubyArg {
	trimmed := trimArgumentTokens(tokens)
	if len(trimmed) == 0 {
		return rubyArg{kind: rubyArgUnknown}
	}
	arg := rubyArg{raw: tokensToString(trimmed)}
	first := trimmed[0]
	switch first.kind {
	case rubyTokenString, rubyTokenNumber:
		arg.kind = rubyArgLiteral
		return arg
	case rubyTokenSymbol:
		arg.kind = rubyArgSymbolArg
		arg.name = strings.TrimPrefix(first.text, ":")
		return arg
	case rubyTokenKeyword:
		if first.text == "true" || first.text == "false" || first.text == "nil" {
			arg.kind = rubyArgLiteral
			return arg
		}
	case rubyTokenOperator:
		switch first.text {
		case "&":
			arg.kind = rubyArgBlockPass
			return arg
		case "*", "**":
			arg.kind = rubyArgSplat
			return arg
		}
	}
	if first.kind == rubyTokenIdentifier || first.kind == rubyTokenConstant {
		name := first.text
		if idx := paramIndexByName(method, name); idx >= 0 {
			arg.kind = rubyArgParameter
			arg.name = name
			arg.paramIndex = idx
			return arg
		}
		if len(trimmed) > 1 {
			second := trimmed[1]
			if second.kind == rubyTokenOperator && (second.text == ":" || second.text == "=>") {
				arg.kind = rubyArgKeywordHash
				arg.name = name
				return arg
			}
		}
		arg.kind = rubyArgIdentifier
		arg.name = name
		return arg
	}
	return arg
}

func trimArgumentTokens(tokens []rubyToken) []rubyToken {
	out := make([]rubyToken, 0, len(tokens))
	for _, tok := range tokens {
		switch tok.kind {
		case rubyTokenNewline, rubyTokenComma:
			continue
		}
		if tok.kind == rubyTokenOperator && strings.TrimSpace(tok.text) == "" {
			continue
		}
		out = append(out, tok)
	}
	return out
}

func tokensToString(tokens []rubyToken) string {
	if len(tokens) == 0 {
		return ""
	}
	var b strings.Builder
	for _, tok := range tokens {
		b.WriteString(tok.text)
	}
	return b.String()
}

// tokenLocation converts a rubyToken to a Location for the IR
func tokenLocation(tok rubyToken, filename string) Location {
	return Location{
		File:   filename,
		Line:   tok.line,
		Column: tok.column,
	}
}

func paramIndexByName(method *rubyMethod, name string) int {
	if method == nil || name == "" {
		return -1
	}
	for i, param := range method.params {
		if param.name == name {
			return i
		}
	}
	return -1
}

func isArgumentToken(tok rubyToken) bool {
	switch tok.kind {
	case rubyTokenIdentifier, rubyTokenConstant, rubyTokenString, rubyTokenNumber, rubyTokenSymbol:
		return true
	case rubyTokenOperator:
		if tok.text == "*" || tok.text == "**" || tok.text == "&" {
			return true
		}
	}
	return false
}

func (p *rubyParser) applyMethodRules(method *rubyMethod) {
	for _, rule := range p.dslRules {
		rule.ApplyMethod(method)
	}
}

func (p *rubyParser) applyCallRules(call *rubyCall, method *rubyMethod) {
	for _, rule := range p.dslRules {
		rule.ApplyCall(call, method)
	}
}

func (p *rubyParser) extractReceiver(idx int) (string, bool) {
	i := p.previousNonNewline(idx)
	if i < 0 {
		return "", false
	}
	tok := p.tokens[i]
	if tok.kind == rubyTokenKeyword && tok.text == "self" {
		return p.currentReceiver(), true
	}
	if tok.kind != rubyTokenIdentifier && tok.kind != rubyTokenConstant {
		return tok.text, true
	}
	parts := []string{tok.text}
	j := p.previousNonNewline(i - 1)
	for j >= 0 {
		sep := p.tokens[j]
		if sep.kind != rubyTokenDoubleColon {
			break
		}
		j = p.previousNonNewline(j - 1)
		if j < 0 {
			break
		}
		segment := p.tokens[j]
		if segment.kind != rubyTokenIdentifier && segment.kind != rubyTokenConstant {
			break
		}
		parts = append([]string{segment.text}, parts...)
		j = p.previousNonNewline(j - 1)
	}
	return strings.Join(parts, "::"), true
}

func (p *rubyParser) previousNonNewline(idx int) int {
	for idx >= 0 {
		if p.tokens[idx].kind != rubyTokenNewline {
			return idx
		}
		idx--
	}
	return -1
}

func (p *rubyParser) nextNonNewline(idx int) int {
	for idx < len(p.tokens) {
		if p.tokens[idx].kind != rubyTokenNewline {
			return idx
		}
		idx++
	}
	return -1
}

func (p *rubyParser) nextSignificant() rubyToken {
	i := p.nextNonNewline(p.pos)
	if i < 0 {
		return rubyToken{kind: rubyTokenEOF}
	}
	tok := p.tokens[i]
	p.pos = i + 1
	return tok
}

func (p *rubyParser) matchOperator(op string) bool {
	if p.peek().kind == rubyTokenOperator && p.peek().text == op {
		p.advance()
		return true
	}
	if op == "." && p.peek().kind == rubyTokenDot {
		p.advance()
		return true
	}
	return false
}

func (p *rubyParser) matchDoubleColon() bool {
	if p.peek().kind == rubyTokenDoubleColon {
		p.advance()
		return true
	}
	return false
}

func (p *rubyParser) advance() rubyToken {
	tok := p.tokens[p.pos]
	if p.pos < len(p.tokens)-1 {
		p.pos++
	}
	return tok
}

func (p *rubyParser) peek() rubyToken {
	if p.pos >= len(p.tokens) {
		return rubyToken{kind: rubyTokenEOF}
	}
	return p.tokens[p.pos]
}

func (p *rubyParser) isEOF() bool {
	return p.peek().kind == rubyTokenEOF
}

func (p *rubyParser) currentReceiver() string {
	if len(p.scopeParts) == 0 {
		return "Object"
	}
	return strings.Join(p.scopeParts, "::")
}

func (p *rubyParser) currentDefault() rubyMethodType {
	if len(p.methodDefaults) == 0 {
		return rubyMethodTopLevel
	}
	return p.methodDefaults[len(p.methodDefaults)-1]
}

func (p *rubyParser) currentVisibility() rubyVisibility {
	if len(p.visibility) == 0 {
		return rubyVisibilityPublic
	}
	return p.visibility[len(p.visibility)-1]
}

func receiverOrDefault(recv string) string {
	if strings.TrimSpace(recv) == "" {
		return "Object"
	}
	return recv
}

func canonicalMethodKey(m *rubyMethod) string {
	return canonicalCallKey(m.receiver, m.name, m.typ)
}

func canonicalCallKey(receiver, name string, typ rubyMethodType) string {
	recv := receiverOrDefault(receiver)
	switch typ {
	case rubyMethodClass:
		return recv + "." + name
	case rubyMethodInstance:
		return recv + "#" + name
	default:
		return recv + "#" + name
	}
}

func rubyMethodSymbolID(pkg string, method *rubyMethod) SymbolID {
	return SymbolID{Dialect: "ruby", Package: pkg, Name: method.name, Recv: receiverOrDefault(method.receiver)}
}

func methodDisplayName(method *rubyMethod) string {
	recv := receiverOrDefault(method.receiver)
	switch method.typ {
	case rubyMethodClass:
		return recv + "." + method.name
	case rubyMethodInstance:
		return recv + "#" + method.name
	default:
		return method.name
	}
}

func methodDisplayFromCall(call rubyCall) string {
	recv := receiverOrDefault(call.receiver)
	switch call.typ {
	case rubyMethodClass:
		return recv + "." + call.name
	case rubyMethodInstance:
		return recv + "#" + call.name
	default:
		return call.name
	}
}
