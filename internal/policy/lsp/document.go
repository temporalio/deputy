package lsp

import (
	"sync"

	protocol "github.com/sourcegraph/go-lsp"
)

// document holds the current state of an open text document.
type document struct {
	uri     protocol.DocumentURI
	text    string
	version int
	lines   []int // rune offsets per line start
	mu      sync.RWMutex
}

func newDocument(uri protocol.DocumentURI, text string, version int) *document {
	d := &document{uri: uri}
	d.update(text, version)
	return d
}

func (d *document) update(text string, version int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.text = text
	d.version = version
	d.lines = buildLineOffsets(text)
}

func (d *document) get() (string, int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.text, d.version
}

func (d *document) position(offset int) protocol.Position {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return offsetToPosition(offset, d.lines)
}

// documentStore tracks open documents keyed by URI.
type documentStore struct {
	mu   sync.RWMutex
	docs map[protocol.DocumentURI]*document
}

func newDocumentStore() *documentStore {
	return &documentStore{docs: make(map[protocol.DocumentURI]*document)}
}

func (s *documentStore) open(uri protocol.DocumentURI, text string, version int) *document {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc := newDocument(uri, text, version)
	s.docs[uri] = doc
	return doc
}

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

func (s *documentStore) get(uri protocol.DocumentURI) (*document, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	doc, ok := s.docs[uri]
	return doc, ok
}

func buildLineOffsets(text string) []int {
	offsets := []int{0}
	for i, r := range text {
		if r == '\n' {
			offsets = append(offsets, i+1)
		}
	}
	return offsets
}

// offsetToPosition converts a rune offset into an LSP position given a line
// offset index. The offsets slice must contain rune indices of line starts.
func offsetToPosition(offset int, lineOffsets []int) protocol.Position {
	// Find line via binary search on offsets slice.
	lo, hi := 0, len(lineOffsets)-1
	for lo <= hi {
		mid := (lo + hi) / 2
		if lineOffsets[mid] <= offset {
			if mid == len(lineOffsets)-1 || lineOffsets[mid+1] > offset {
				return protocol.Position{
					Line:      mid,
					Character: offset - lineOffsets[mid],
				}
			}
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	// Fallback to end of text.
	if len(lineOffsets) == 0 {
		return protocol.Position{}
	}
	last := len(lineOffsets) - 1
	return protocol.Position{Line: last, Character: 0}
}
