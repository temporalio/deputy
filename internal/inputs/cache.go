package inputs

import "fmt"

// cache is a generic cache for parsed manifest files.
// It stores both successful parses and errors to avoid repeated parsing attempts.
// The parser function is called on cache miss to parse the file content.
type cache[T any] struct {
	resolver Resolver
	parser   func([]byte) (T, error)
	entries  map[string]T
	errs     map[string]error
}

// newCache creates a new manifest cache with the given resolver and parser.
// Returns nil if resolver is nil.
func newCache[T any](resolver Resolver, parser func([]byte) (T, error)) *cache[T] {
	if resolver == nil {
		return nil
	}
	return &cache[T]{
		resolver: resolver,
		parser:   parser,
		entries:  make(map[string]T),
		errs:     make(map[string]error),
	}
}

// get retrieves a parsed manifest from the cache, parsing it on first access.
// Both successful parses and errors are cached.
func (c *cache[T]) get(path string) (T, error) {
	var zero T
	if c == nil {
		return zero, fmt.Errorf("no resolver")
	}
	if data, ok := c.entries[path]; ok {
		return data, nil
	}
	if err, ok := c.errs[path]; ok {
		return zero, err
	}
	content, err := c.resolver.ReadFile(path)
	if err != nil {
		c.errs[path] = err
		return zero, err
	}
	data, err := c.parser(content)
	if err != nil {
		c.errs[path] = err
		return zero, err
	}
	c.entries[path] = data
	return data, nil
}
