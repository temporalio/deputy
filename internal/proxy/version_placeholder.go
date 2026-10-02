package proxy

import "github.com/temporalio/deputy/internal/policy"

// unknownVersionPlaceholder is used when a request has no concrete version.
// This prevents policies from treating an empty string as a match-all pattern.
// The value is defined by the policy payload contract, which also has to know
// the sentinel so it survives version normalization.
const unknownVersionPlaceholder = policy.UnknownVersion
