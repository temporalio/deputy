// Package collections provides generic collection utilities for Deputy.
//
// This package contains reusable generic functions for working with slices,
// maps, and other collections. These utilities complement the standard library's
// slices and maps packages.
//
// # Slice Operations
//
// Common slice transformations:
//
//	// Map a function over a slice
//	names := collections.Map(users, func(u User) string { return u.Name })
//
//	// Filter elements matching a predicate
//	active := collections.Filter(users, func(u User) bool { return u.Active })
//
//	// Check if any/all elements match
//	hasAdmin := collections.Any(users, func(u User) bool { return u.Role == "admin" })
//
// # Set Operations
//
// Working with sets represented as maps:
//
//	// Create a set from a slice
//	seen := collections.ToSet(items)
//
//	// Check membership
//	if seen["item"] {
//	    // item exists
//	}
//
// # Deduplication
//
// Remove duplicates from slices:
//
//	unique := collections.Unique(items)
//	uniqueBy := collections.UniqueBy(users, func(u User) string { return u.Email })
package collections
