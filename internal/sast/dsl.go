package sast

import "strings"

// DSLRule describes heuristics that can augment call metadata or tag methods
// when specific DSL patterns are observed (for example Rails callbacks or
// background job declarations).
type DSLRule interface {
	Dialect() string
	ApplyMethod(method *rubyMethod)
	ApplyCall(call *rubyCall, method *rubyMethod)
}

// DSLRegistry stores DSL rules keyed by dialect. Dialects can use the registry
// to extend analysis without coupling their parser to ecosystem specifics.
type DSLRegistry struct {
	rules map[string][]DSLRule
}

// NewDSLRegistry constructs an empty DSL registry.
func NewDSLRegistry() *DSLRegistry {
	return &DSLRegistry{rules: make(map[string][]DSLRule)}
}

// Register adds a rule to the registry.
func (r *DSLRegistry) Register(rule DSLRule) {
	if rule == nil {
		return
	}
	dialect := strings.ToLower(rule.Dialect())
	r.rules[dialect] = append(r.rules[dialect], rule)
}

// RulesFor returns the rules registered for a dialect.
func (r *DSLRegistry) RulesFor(dialect string) []DSLRule {
	return append([]DSLRule(nil), r.rules[strings.ToLower(dialect)]...)
}

var globalDSLRegistry = NewDSLRegistry()

// GlobalDSLRegistry exposes the shared registry accessed by dialects. Tests can
// replace this registry if isolation is required.
func GlobalDSLRegistry() *DSLRegistry {
	return globalDSLRegistry
}

// RegisterRubyDefaults seeds the registry with heuristics tuned for common Ruby
// frameworks.
func RegisterRubyDefaults() {
	GlobalDSLRegistry().Register(&railsCallbackRule{})
	GlobalDSLRegistry().Register(&railsStrongParamsRule{})
}

func init() {
	RegisterRubyDefaults()
}

type railsCallbackRule struct{}

type railsCallbackMetadata struct {
	Callback string
}

func (railsCallbackRule) Dialect() string { return "ruby" }

func (railsCallbackRule) ApplyMethod(method *rubyMethod) {
	// no-op
}

func (railsCallbackRule) ApplyCall(call *rubyCall, method *rubyMethod) {
	switch call.name {
	case "before_action", "after_action", "around_action",
		"before_filter", "after_filter", "around_filter",
		"prepend_before_action", "append_before_action":
		if len(call.symbolArgs) == 0 {
			return
		}
		call.confidence = maxConfidence(call.confidence, EdgeConfidenceProbable)
		call.dynamic = true
		if call.metadata == nil {
			call.metadata = make(map[string]any)
		}
		call.metadata["rails_callback"] = call.symbolArgs
	case "helper_method":
		call.confidence = maxConfidence(call.confidence, EdgeConfidenceProbable)
		call.dynamic = true
		if call.metadata == nil {
			call.metadata = make(map[string]any)
		}
		call.metadata["rails_helper"] = call.symbolArgs
	}
}

type railsStrongParamsRule struct{}

func (railsStrongParamsRule) Dialect() string { return "ruby" }

func (railsStrongParamsRule) ApplyMethod(method *rubyMethod) {
	if method == nil || method.attributes == nil {
		return
	}
	if strings.HasSuffix(method.name, "_params") {
		method.attributes["rails_strong_params"] = true
	}
}

func (railsStrongParamsRule) ApplyCall(call *rubyCall, method *rubyMethod) {
	if call.name == "permit" || call.name == "require" {
		call.metadata = mergeMetadata(call.metadata, map[string]any{"strong_params": true})
	}
}

func maxConfidence(a, b EdgeConfidence) EdgeConfidence {
	if confidenceWeight(a) >= confidenceWeight(b) {
		return a
	}
	return b
}
