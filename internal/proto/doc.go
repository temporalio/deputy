// Package proto provides bidirectional conversion between Deputy's internal
// domain types and their protobuf representations.
//
// This package serves as the boundary between the internal Go types used
// throughout Deputy's codebase and the generated protobuf types in gen/deputy/*/v1.
// All conversions maintain fidelity and are designed to be zero-allocation
// where possible.
//
// # Usage
//
// Convert internal scan results to proto for transmission:
//
//	result := scan.Result{...}
//	protoResult := proto.ScanResponseFromInternal(&result)
//
// Convert incoming proto requests to internal types:
//
//	req := &scanv1.ScanRequest{...}
//	target, opts := proto.ScanRequestToInternal(req)
//
// # Design Principles
//
//   - Converters are pure functions with no side effects
//   - Nil inputs produce nil outputs (safe for optional fields)
//   - Proto types are always fully populated (no nil embedded messages)
//   - Internal types use pointers for optional fields
package proto
