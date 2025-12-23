// Package collections provides small generic helpers that are shared across the
// codebase.
package collections

import (
	"iter"
	"maps"
	"slices"
	"strings"
)

// NormalizeLower returns a lowercase, trimmed version of the input string.
// This is a common pattern used throughout the codebase for case-insensitive
// comparisons and key normalization.
func NormalizeLower(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// NormalizeUpper returns an uppercase, trimmed version of the input string.
// Use this for case-insensitive comparisons where uppercase is the convention
// (e.g., severity levels like "HIGH", "CRITICAL").
func NormalizeUpper(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// Set is a lightweight generic set implementation backed by a map.
//
// The zero value is a nil map. Use [NewSet] (or make(Set[T])) before calling
// [Set.Add].
type Set[T comparable] map[T]struct{}

// NewSet returns a new [Set] populated with the provided values.
func NewSet[T comparable](values ...T) Set[T] {
	set := make(Set[T], len(values))
	for _, v := range values {
		set.Add(v)
	}
	return set
}

// NewSetWithCapacity returns a new empty [Set] with pre-allocated capacity.
// Use this when you know the approximate number of elements to avoid reallocations.
func NewSetWithCapacity[T comparable](capacity int) Set[T] {
	return make(Set[T], capacity)
}

// NewSetFunc creates a Set by applying a transform function to each element.
// Elements that transform to the zero value are skipped. Returns nil if the
// resulting set is empty.
func NewSetFunc[T, U comparable](items []T, transform func(T) U) Set[U] {
	if len(items) == 0 {
		return nil
	}
	var zero U
	set := make(Set[U], len(items))
	for _, item := range items {
		if v := transform(item); v != zero {
			set[v] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// Add inserts v and reports whether it was newly added.
func (s Set[T]) Add(v T) bool {
	_, existed := s[v]
	s[v] = struct{}{}
	return !existed
}

// Has reports whether v is present in the set.
func (s Set[T]) Has(v T) bool {
	_, ok := s[v]
	return ok
}

// All returns an iterator over all elements in the set.
//
// Iteration order is not defined.
func (s Set[T]) All() iter.Seq[T] {
	return maps.Keys(s)
}

// Slice returns all elements in the set as a slice.
//
// Order is not defined. For stable results, sort the returned slice.
func (s Set[T]) Slice() []T {
	return slices.Collect(s.All())
}

// Len returns the number of elements in the set.
func (s Set[T]) Len() int {
	return len(s)
}

// Dedupe returns a new slice containing only the first occurrence of each element,
// preserving the original order. This is useful when order matters.
func Dedupe[T comparable](items []T) []T {
	if len(items) == 0 {
		return nil
	}
	seen := NewSetWithCapacity[T](len(items))
	result := make([]T, 0, len(items))
	for _, item := range items {
		if seen.Add(item) {
			result = append(result, item)
		}
	}
	return result
}

// DedupeFunc returns a new slice containing only the first occurrence of each element
// based on a key function, preserving the original order. This is useful when you need
// to deduplicate based on a derived key rather than the element itself.
func DedupeFunc[T any, K comparable](items []T, key func(T) K) []T {
	if len(items) == 0 {
		return nil
	}
	seen := NewSetWithCapacity[K](len(items))
	result := make([]T, 0, len(items))
	for _, item := range items {
		k := key(item)
		if seen.Add(k) {
			result = append(result, item)
		}
	}
	return result
}

// Merge combines multiple slices into one, removing duplicates while preserving
// the order of first occurrence.
func Merge[T comparable](slices ...[]T) []T {
	// Calculate total capacity
	total := 0
	for _, s := range slices {
		total += len(s)
	}
	if total == 0 {
		return nil
	}

	seen := NewSetWithCapacity[T](total)
	result := make([]T, 0, total)
	for _, slice := range slices {
		for _, item := range slice {
			if seen.Add(item) {
				result = append(result, item)
			}
		}
	}
	return result
}

// MergeFunc combines multiple slices into one, removing duplicates based on a key function
// while preserving the order of first occurrence.
func MergeFunc[T any, K comparable](key func(T) K, slices ...[]T) []T {
	total := 0
	for _, s := range slices {
		total += len(s)
	}
	if total == 0 {
		return nil
	}

	seen := NewSetWithCapacity[K](total)
	result := make([]T, 0, total)
	for _, slice := range slices {
		for _, item := range slice {
			k := key(item)
			if seen.Add(k) {
				result = append(result, item)
			}
		}
	}
	return result
}

// Filter returns elements that pass the predicate, with duplicates removed.
// Order of first occurrence is preserved.
func Filter[T comparable](items []T, predicate func(T) bool) []T {
	if len(items) == 0 {
		return nil
	}
	seen := NewSetWithCapacity[T](len(items))
	result := make([]T, 0, len(items))
	for _, item := range items {
		if predicate(item) && seen.Add(item) {
			result = append(result, item)
		}
	}
	return result
}
