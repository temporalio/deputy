package lsp

import (
	"sync"

	protocol "github.com/sourcegraph/go-lsp"
)

// document holds the current state of an open text document, including its
// content, version, and line offsets for efficient position calculations.
// It is safe for concurrent use.
type document struct {
	uri     protocol.DocumentURI
	text    string
	version int
	lines   []int // rune offsets per line start
	mu      sync.RWMutex
}

// newDocument creates a new document instance with the given URI, text content,
// and version number. It initializes the line offsets for the document.
func newDocument(uri protocol.DocumentURI, text string, version int) *document {
	d := &document{uri: uri}
	d.update(text, version)
	return d
}

// update refreshes the document's content and version. It recalculates the
// line offsets based on the new text.
func (d *document) update(text string, version int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.text = text
	d.version = version
	d.lines = buildLineOffsets(text)
}

// get returns the current text content and version of the document.
func (d *document) get() (string, int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.text, d.version
}

// documentStore tracks open documents keyed by their URI. It provides thread-safe
// access to manage the lifecycle of documents.
type documentStore struct {
	mu   sync.RWMutex
	docs map[protocol.DocumentURI]*document
}

// newDocumentStore creates a new, empty document store.
func newDocumentStore() *documentStore {
	return &documentStore{docs: make(map[protocol.DocumentURI]*document)}
}

// open adds a new document to the store or updates an existing one with the
// provided text and version. It returns the document instance.
func (s *documentStore) open(uri protocol.DocumentURI, text string, version int) *document {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc := newDocument(uri, text, version)
	s.docs[uri] = doc
	return doc
}

// update modifies the content and version of an existing document in the store.
// It returns the updated document and true if found, or nil and false otherwise.
func (s *documentStore) update(uri protocol.DocumentURI, text string, version int) (*document, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc, ok := s.docs[uri]
	if !ok {
		return nil, false
	}
	doc.update(text, version)
	return doc, true
}

// get retrieves a document from the store by its URI. It returns the document
// and true if found, or nil and false otherwise.
func (s *documentStore) get(uri protocol.DocumentURI) (*document, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	doc, ok := s.docs[uri]
	return doc, ok
}

// buildLineOffsets calculates the rune offsets for the start of each line in the text.
// This allows for efficient mapping between offsets and line/character positions.
func buildLineOffsets(text string) []int {
	offsets := []int{0}
	for i, r := range text {
		if r == '\n' {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}
