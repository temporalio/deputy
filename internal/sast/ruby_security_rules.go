package sast

import (
	"strings"
)

// rubySecurityRule implements comprehensive security pattern detection for Ruby
type rubySecurityRule struct{}

func (rubySecurityRule) Dialect() string { return "ruby" }

func (rubySecurityRule) ApplyMethod(method *rubyMethod) {
	if method == nil {
		return
	}

	// Mark security-sensitive methods
	if isSecuritySensitiveMethod(method.name) {
		if method.attributes == nil {
			method.attributes = make(map[string]any)
		}
		method.attributes["security_sensitive"] = true
	}

	// Detect potential entry points for security analysis
	if isControllerMethod(method) {
		if method.attributes == nil {
			method.attributes = make(map[string]any)
		}
		method.attributes["controller_action"] = true
		method.attributes["entry_point"] = true
	}
}

func (rubySecurityRule) ApplyCall(call *rubyCall, method *rubyMethod) {
	if call == nil {
		return
	}

	// Debug output
	// fmt.Printf("DEBUG: Checking call %s.%s\n", call.receiver, call.name)

	// Command injection patterns
	if isCommandInjectionSink(call.name, call.receiver) {
		// fmt.Printf("DEBUG: Found command injection sink: %s.%s\n", call.receiver, call.name)
		call.metadata = mergeSecurityMetadata(call.metadata, map[string]any{
			"vulnerability_type": "command_injection",
			"severity":           "high",
			"cwe":                "CWE-78",
		})
		call.confidence = EdgeConfidenceCertain
	}

	// SQL injection patterns
	if isSqlInjectionSink(call.name, call.receiver) {
		call.metadata = mergeSecurityMetadata(call.metadata, map[string]any{
			"vulnerability_type": "sql_injection",
			"severity":           "high",
			"cwe":                "CWE-89",
		})
		call.confidence = EdgeConfidenceCertain
	}

	// XSS patterns
	if isXssSink(call.name, call.receiver) {
		call.metadata = mergeSecurityMetadata(call.metadata, map[string]any{
			"vulnerability_type": "xss",
			"severity":           "medium",
			"cwe":                "CWE-79",
		})
		call.confidence = EdgeConfidenceProbable
	}

	// Path traversal patterns
	if isPathTraversalSink(call.name, call.receiver) {
		call.metadata = mergeSecurityMetadata(call.metadata, map[string]any{
			"vulnerability_type": "path_traversal",
			"severity":           "high",
			"cwe":                "CWE-22",
		})
		call.confidence = EdgeConfidenceCertain
	}

	// Code injection patterns
	if isCodeInjectionSink(call.name, call.receiver) {
		call.metadata = mergeSecurityMetadata(call.metadata, map[string]any{
			"vulnerability_type": "code_injection",
			"severity":           "critical",
			"cwe":                "CWE-94",
		})
		call.confidence = EdgeConfidenceCertain
	}

	// Deserialization vulnerabilities
	if isUnsafeDeserializationSink(call.name, call.receiver) {
		call.metadata = mergeSecurityMetadata(call.metadata, map[string]any{
			"vulnerability_type": "unsafe_deserialization",
			"severity":           "critical",
			"cwe":                "CWE-502",
		})
		call.confidence = EdgeConfidenceCertain
	}

	// Weak cryptography patterns
	if isWeakCryptographySink(call.name, call.receiver) {
		call.metadata = mergeSecurityMetadata(call.metadata, map[string]any{
			"vulnerability_type": "weak_cryptography",
			"severity":           "medium",
			"cwe":                "CWE-327",
		})
		call.confidence = EdgeConfidenceProbable
	}

	// Information disclosure patterns
	if isInformationDisclosureSink(call.name, call.receiver) {
		call.metadata = mergeSecurityMetadata(call.metadata, map[string]any{
			"vulnerability_type": "information_disclosure",
			"severity":           "low",
			"cwe":                "CWE-200",
		})
		call.confidence = EdgeConfidencePossible
	}

	// Taint sources
	if isTaintSource(call.name, call.receiver) {
		call.metadata = mergeSecurityMetadata(call.metadata, map[string]any{
			"taint_source": true,
			"source_type":  getTaintSourceType(call.name, call.receiver),
		})
	}

	// Sanitization functions
	if isSanitizer(call.name, call.receiver) {
		call.metadata = mergeSecurityMetadata(call.metadata, map[string]any{
			"sanitizer":    true,
			"sanitizes":    getSanitizationTypes(call.name, call.receiver),
			"trusted_sink": true,
		})
	}
}

// Command injection detection
func isCommandInjectionSink(name, receiver string) bool {
	// fmt.Printf("DEBUG: isCommandInjectionSink checking name='%s', receiver='%s'\n", name, receiver)

	// Kernel methods that can be called from any object
	kernelMethods := []string{"system", "exec", "spawn", "`", "%x"}
	for _, method := range kernelMethods {
		if name == method {
			return true
		}
	}

	commandMethods := map[string][]string{
		"IO":         {"popen"},
		"File":       {"popen"},
		"Open3":      {"capture2", "capture2e", "capture3", "popen2", "popen2e", "popen3"},
		"Process":    {"spawn"},
		"Subprocess": {"check_call", "check_output", "call", "run"},
	}

	if methods, ok := commandMethods[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}
	return false
}

// SQL injection detection
func isSqlInjectionSink(name, receiver string) bool {
	sqlMethods := map[string][]string{
		"ActiveRecord::Base":     {"find_by_sql", "execute", "select_all", "select_one", "select_rows", "select_values"},
		"ActiveRecord::Relation": {"where", "having", "order", "group", "joins", "select", "from"},
		"User":                   {"where", "find_by_sql", "order", "group", "having", "joins"},
		"Post":                   {"where", "find_by_sql", "order", "group", "having", "joins"},
		"Model":                  {"where", "find_by_sql", "order", "group", "having", "joins"},
		"DB":                     {"[]"}, // Sequel
	}

	if methods, ok := sqlMethods[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	// Generic ActiveRecord model methods
	if receiver != "" && (strings.HasSuffix(receiver, "Model") || isActiveRecordModel(receiver)) {
		sqlMethodNames := []string{"where", "find_by_sql", "order", "group", "having", "joins", "select", "from"}
		for _, method := range sqlMethodNames {
			if name == method {
				return true
			}
		}
	}

	return false
}

// XSS detection
func isXssSink(name, receiver string) bool {
	// Global XSS sinks - these methods can be called from any context
	globalSinks := []string{"render", "html_safe", "raw"}
	for _, sink := range globalSinks {
		if name == sink {
			return true
		}
	}

	xssMethods := map[string][]string{
		"ActionController::Base": {"render"},
		"ApplicationController":  {"render"},
		"Controller":             {"render"},
		"ActionView::Base":       {"raw", "content_tag", "link_to"},
		"ERB":                    {"result"},
	}

	if methods, ok := xssMethods[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	// String methods that can create XSS
	if receiver == "String" && (name == "html_safe" || name == "+") {
		return true
	}

	return false
}

// Path traversal detection
func isPathTraversalSink(name, receiver string) bool {
	pathMethods := map[string][]string{
		"File":                   {"read", "open", "write", "exists?", "exist?", "directory?", "size", "expand_path", "realpath"},
		"IO":                     {"read", "open", "write", "foreach"},
		"Dir":                    {"glob", "entries", "mkdir", "rmdir"},
		"FileUtils":              {"mkdir_p", "rm_rf", "cp", "mv"},
		"ActionController::Base": {"send_file", "send_data"},
		"ApplicationController":  {"send_file", "send_data"},
		"":                       {"require", "load", "autoload"},
	}

	if methods, ok := pathMethods[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	return false
}

// Code injection detection
func isCodeInjectionSink(name, receiver string) bool {
	// Global methods that can be called from any object
	globalMethods := []string{"eval", "instance_eval", "class_eval", "module_eval", "send", "public_send", "__send__", "const_get"}
	for _, method := range globalMethods {
		if name == method {
			return true
		}
	}

	codeMethods := map[string][]string{
		"BasicObject": {"instance_eval"},
		"Class":       {"class_eval"},
		"Module":      {"module_eval", "const_get"},
		"ERB":         {"new", "result"},
		"Proc":        {"new"},
	}

	if methods, ok := codeMethods[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	return false
}

// Unsafe deserialization detection
func isUnsafeDeserializationSink(name, receiver string) bool {
	deserializationMethods := map[string][]string{
		"YAML":    {"load", "unsafe_load"},
		"Psych":   {"load", "unsafe_load"},
		"Marshal": {"load", "restore"},
		"JSON":    {"load"},
	}

	if methods, ok := deserializationMethods[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	// JSON.parse with unsafe options
	if receiver == "JSON" && name == "parse" {
		return true // Will need to check arguments for create_additions: true
	}

	return false
}

// Weak cryptography detection
func isWeakCryptographySink(name, receiver string) bool {
	weakCryptoMethods := map[string][]string{
		"Digest":          {"MD5", "SHA1"},
		"OpenSSL::Digest": {"MD5", "SHA1"},
		"SecureRandom":    {}, // Some methods might be weak depending on usage
		"Random":          {"rand", "srand"},
		"":                {"rand", "srand"},
	}

	if methods, ok := weakCryptoMethods[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	return false
}

// Information disclosure detection
func isInformationDisclosureSink(name, receiver string) bool {
	disclosureMethods := map[string][]string{
		"":          {"p", "puts", "print", "pp"},
		"Kernel":    {"p", "puts", "print", "pp"},
		"Object":    {"inspect", "to_s"},
		"Exception": {"backtrace", "message"},
		"Binding":   {"irb"},
	}

	if methods, ok := disclosureMethods[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	return false
}

// Taint source detection
func isTaintSource(name, receiver string) bool {
	// Global taint sources
	globalSources := []string{"params", "cookies", "session", "request", "env"}
	for _, source := range globalSources {
		if name == source {
			return true
		}
	}

	taintSources := map[string][]string{
		"ActionController::Parameters": {"[]", "permit", "require"},
		"Hash":                         {"[]"},
		"ENV":                          {"[]", "fetch"},
		"ARGV":                         {},
		"File":                         {"read", "readlines"},
		"IO":                           {"read", "gets", "readlines"},
		"STDIN":                        {"read", "gets", "readlines"},
	}

	if methods, ok := taintSources[receiver]; ok {
		if len(methods) == 0 {
			return true // All methods are taint sources
		}
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	return false
}

// Sanitization detection
func isSanitizer(name, receiver string) bool {
	// Global sanitizer functions (can be called from any context)
	globalSanitizers := []string{"sanitize_input", "sanitize", "escape", "clean"}
	for _, sanitizer := range globalSanitizers {
		if name == sanitizer {
			return true
		}
	}

	sanitizers := map[string][]string{
		"ActionView::Helpers::TagHelper": {"html_escape", "h"},
		"ERB::Util":                      {"html_escape", "h"},
		"CGI":                            {"escapeHTML", "escape"},
		"Rack::Utils":                    {"escape_html"},
		"ActiveRecord::Base":             {"sanitize_sql", "sanitize_sql_like", "quote"},
		"Shellwords":                     {"escape", "shellescape"},
		"File":                           {"basename"},
		"YAML":                           {"safe_load"},
		"JSON":                           {"parse"}, // Safe by default without create_additions
	}

	if methods, ok := sanitizers[receiver]; ok {
		for _, method := range methods {
			if name == method {
				return true
			}
		}
	}

	return false
}

// Helper functions
func isSecuritySensitiveMethod(name string) bool {
	sensitivePatterns := []string{
		"authenticate", "authorize", "login", "logout", "password", "token",
		"secret", "key", "encrypt", "decrypt", "hash", "verify", "validate",
		"permit", "admin", "root", "sudo", "exec", "eval", "system",
	}

	lowerName := strings.ToLower(name)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}
	return false
}

func isControllerMethod(method *rubyMethod) bool {
	if method.receiver == "" {
		return false
	}

	controllerPatterns := []string{"Controller", "controller"}
	for _, pattern := range controllerPatterns {
		if strings.Contains(method.receiver, pattern) {
			return true
		}
	}
	return false
}

func isActiveRecordModel(receiver string) bool {
	// Heuristic: capitalized class names that might be ActiveRecord models
	if len(receiver) > 0 && receiver[0] >= 'A' && receiver[0] <= 'Z' {
		return true
	}
	return false
}

func getTaintSourceType(name, receiver string) string {
	if receiver == "ActionController::Parameters" || name == "params" {
		return "user_input"
	}
	if name == "cookies" || name == "session" {
		return "user_data"
	}
	if receiver == "ENV" || receiver == "ARGV" {
		return "environment"
	}
	if receiver == "File" || receiver == "IO" {
		return "file_input"
	}
	return "unknown"
}

func getSanitizationTypes(name, receiver string) []string {
	switch {
	case name == "html_escape" || name == "h":
		return []string{"xss"}
	case name == "sanitize_sql" || name == "sanitize_sql_like":
		return []string{"sql_injection"}
	case name == "escape" || name == "shellescape":
		return []string{"command_injection"}
	case name == "basename":
		return []string{"path_traversal"}
	case name == "safe_load":
		return []string{"code_injection", "deserialization"}
	default:
		return []string{"generic"}
	}
}

func mergeSecurityMetadata(existing map[string]any, new map[string]any) map[string]any {
	if existing == nil {
		existing = make(map[string]any)
	}
	for k, v := range new {
		existing[k] = v
	}
	return existing
}

func init() {
	// Register the security rule
	GlobalDSLRegistry().Register(&rubySecurityRule{})
}
