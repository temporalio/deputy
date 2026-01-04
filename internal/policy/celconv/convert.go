// Package celconv provides type conversion utilities for CEL (Common Expression Language).
//
// CEL uses specific type representations that differ from Go's native types.
// This package provides conversion functions to bridge the gap, enabling
// domain types to be evaluated by CEL expressions in policy rules.
//
// # Type Coercion
//
// CEL requires specific types for its operations:
//   - Go's []string must be converted to []any for CEL list operations
//   - Go's map[string]string must be converted to map[string]any for CEL map operations
//
// These conversions are necessary because CEL's type system is more dynamic
// than Go's, and the CEL evaluator expects interface{}/any types for collection
// elements.
//
// # Usage
//
// Domain types that need CEL evaluation should use these functions in their
// ToMap() methods:
//
//	func (c *Config) ToMap() map[string]any {
//	    return map[string]any{
//	        "env":    celconv.ToAnySlice(c.Env),
//	        "labels": celconv.ToAnyMap(c.Labels),
//	    }
//	}
package celconv

// ToAnySlice converts a string slice to []any for CEL compatibility.
//
// CEL's list operations require []any; Go's []string cannot be used directly
// in CEL expressions. This function performs the necessary type widening.
//
// Returns an empty slice (not nil) for nil input to ensure consistent
// CEL behavior - CEL expressions can safely call .size() or iterate
// without nil checks.
func ToAnySlice(s []string) []any {
	if s == nil {
		return []any{}
	}
	result := make([]any, len(s))
	for i, v := range s {
		result[i] = v
	}
	return result
}

// ToAnyMap converts a string map to map[string]any for CEL compatibility.
//
// CEL's map operations require map[string]any; Go's map[string]string cannot
// be used directly in CEL expressions. This function performs the necessary
// type widening.
//
// Returns an empty map (not nil) for nil input to ensure consistent
// CEL behavior - CEL expressions can safely access keys or iterate
// without nil checks.
func ToAnyMap(m map[string]string) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	result := make(map[string]any, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}
