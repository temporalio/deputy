package proxy

// unknownVersionPlaceholder is used when a request has no concrete version.
// This prevents policies from treating an empty string as a match-all pattern.
const unknownVersionPlaceholder = "<unknown>"
