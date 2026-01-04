package celconv

import (
	"testing"
)

func TestToAnySlice(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []any
	}{
		{
			name:  "nil input returns empty slice",
			input: nil,
			want:  []any{},
		},
		{
			name:  "empty slice returns empty slice",
			input: []string{},
			want:  []any{},
		},
		{
			name:  "single element",
			input: []string{"foo"},
			want:  []any{"foo"},
		},
		{
			name:  "multiple elements",
			input: []string{"a", "b", "c"},
			want:  []any{"a", "b", "c"},
		},
		{
			name:  "preserves empty strings",
			input: []string{"", "foo", ""},
			want:  []any{"", "foo", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToAnySlice(tt.input)
			if got == nil {
				t.Fatal("ToAnySlice returned nil, want non-nil slice")
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ToAnySlice() len = %d, want %d", len(got), len(tt.want))
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("ToAnySlice()[%d] = %v, want %v", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestToAnyMap(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]string
		want  map[string]any
	}{
		{
			name:  "nil input returns empty map",
			input: nil,
			want:  map[string]any{},
		},
		{
			name:  "empty map returns empty map",
			input: map[string]string{},
			want:  map[string]any{},
		},
		{
			name:  "single entry",
			input: map[string]string{"key": "value"},
			want:  map[string]any{"key": "value"},
		},
		{
			name:  "multiple entries",
			input: map[string]string{"a": "1", "b": "2", "c": "3"},
			want:  map[string]any{"a": "1", "b": "2", "c": "3"},
		},
		{
			name:  "preserves empty values",
			input: map[string]string{"empty": "", "full": "value"},
			want:  map[string]any{"empty": "", "full": "value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToAnyMap(tt.input)
			if got == nil {
				t.Fatal("ToAnyMap returned nil, want non-nil map")
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ToAnyMap() len = %d, want %d", len(got), len(tt.want))
			}
			for k, v := range tt.want {
				if gotV, ok := got[k]; !ok {
					t.Errorf("ToAnyMap() missing key %q", k)
				} else if gotV != v {
					t.Errorf("ToAnyMap()[%q] = %v, want %v", k, gotV, v)
				}
			}
		})
	}
}
