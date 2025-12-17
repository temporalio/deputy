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
