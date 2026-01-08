package proto

import (
	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
)

// Validate validates a proto message using protovalidate rules defined in the proto schema.
// Returns nil if validation passes, or a validation error describing the failures.
//
// This uses the package-level Validate function from protovalidate, which is safe for
// concurrent use and caches compiled validators for efficient repeated validation.
//
// Example usage:
//
//	req := &remediationv1.ExecuteWithAgentRequest{Agent: ""}
//	if err := proto.Validate(req); err != nil {
//	    return connect.NewError(connect.CodeInvalidArgument, err)
//	}
func Validate(msg proto.Message) error {
	return protovalidate.Validate(msg)
}

// MustValidate validates a proto message and panics if validation fails.
// Use only in tests or initialization code where validation failures indicate programming errors.
func MustValidate(msg proto.Message) {
	if err := Validate(msg); err != nil {
		panic("validation failed: " + err.Error())
	}
}

// IsValid returns true if the message passes validation.
func IsValid(msg proto.Message) bool {
	return Validate(msg) == nil
}
