package inputs

import (
	"errors"
	"testing"
)

// mockResolver implements Resolver for testing.
type mockResolver struct {
	files map[string][]byte
	err   error
}

func (m *mockResolver) ReadFile(path string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	content, ok := m.files[path]
	if !ok {
		return nil, errors.New("file not found")
	}
	return content, nil
}

func TestNewCache(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		resolver Resolver
		wantNil  bool
	}{
		{
			name:     "nil resolver returns nil cache",
			resolver: nil,
			wantNil:  true,
		},
		{
			name:     "valid resolver returns cache",
			resolver: &mockResolver{files: map[string][]byte{}},
			wantNil:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newCache(tt.resolver, func(b []byte) (string, error) {
				return string(b), nil
			})
			if (c == nil) != tt.wantNil {
				t.Errorf("newCache() nil = %v, want nil = %v", c == nil, tt.wantNil)
			}
		})
	}
}

func TestCache_Get(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		files      map[string][]byte
		parseErr   error
		resolveErr error
		path       string
		wantData   string
		wantErr    bool
	}{
		{
			name:     "successful parse",
			files:    map[string][]byte{"test.json": []byte(`{"key": "value"}`)},
			path:     "test.json",
			wantData: `{"key": "value"}`,
			wantErr:  false,
		},
		{
			name:    "file not found",
			files:   map[string][]byte{},
			path:    "missing.json",
			wantErr: true,
		},
		{
			name:       "resolver error",
			files:      map[string][]byte{},
			resolveErr: errors.New("read error"),
			path:       "test.json",
			wantErr:    true,
		},
		{
			name:     "parse error",
			files:    map[string][]byte{"test.json": []byte(`invalid`)},
			parseErr: errors.New("parse error"),
			path:     "test.json",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &mockResolver{files: tt.files, err: tt.resolveErr}
			c := newCache(resolver, func(b []byte) (string, error) {
				if tt.parseErr != nil {
					return "", tt.parseErr
				}
				return string(b), nil
			})

			data, err := c.get(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && data != tt.wantData {
				t.Errorf("get() = %v, want %v", data, tt.wantData)
			}
		})
	}
}

func TestCache_Caching(t *testing.T) {
	t.Parallel()

	callCount := 0
	resolver := &mockResolver{
		files: map[string][]byte{"test.json": []byte(`data`)},
	}
	c := newCache(resolver, func(b []byte) (string, error) {
		callCount++
		return string(b), nil
	})

	// First call should parse
	data1, err := c.get("test.json")
	if err != nil {
		t.Fatalf("first get() error = %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 parse call, got %d", callCount)
	}

	// Second call should use cache
	data2, err := c.get("test.json")
	if err != nil {
		t.Fatalf("second get() error = %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 parse call (cached), got %d", callCount)
	}

	if data1 != data2 {
		t.Errorf("cached data mismatch: %v != %v", data1, data2)
	}
}

func TestCache_ErrorCaching(t *testing.T) {
	t.Parallel()

	callCount := 0
	resolver := &mockResolver{
		files: map[string][]byte{"test.json": []byte(`data`)},
	}
	c := newCache(resolver, func(b []byte) (string, error) {
		callCount++
		return "", errors.New("parse error")
	})

	// First call should fail
	_, err1 := c.get("test.json")
	if err1 == nil {
		t.Fatal("expected error on first call")
	}
	if callCount != 1 {
		t.Errorf("expected 1 parse call, got %d", callCount)
	}

	// Second call should return cached error
	_, err2 := c.get("test.json")
	if err2 == nil {
		t.Fatal("expected cached error on second call")
	}
	if callCount != 1 {
		t.Errorf("expected 1 parse call (error cached), got %d", callCount)
	}
}

func TestCache_NilCache(t *testing.T) {
	t.Parallel()

	var c *cache[string]
	_, err := c.get("test.json")
	if err == nil {
		t.Error("expected error for nil cache")
	}
}
