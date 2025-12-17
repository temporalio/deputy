package collections

import (
	"slices"
	"testing"
)

func TestNewSet_Slice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "nil", in: nil, want: nil},
		{name: "empty", in: []string{}, want: nil},
		{name: "single", in: []string{"a"}, want: []string{"a"}},
		{name: "dedupe", in: []string{"b", "a", "b", "a"}, want: []string{"a", "b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet(tt.in...)
			got := s.Slice()
			slices.Sort(got)

			want := slices.Clone(tt.want)
			slices.Sort(want)

			if !slices.Equal(got, want) {
				t.Fatalf("Slice()=%v want %v", got, want)
			}
		})
	}
}

func TestSet_AddAndHas(t *testing.T) {
	t.Parallel()

	type step struct {
		add      string
		wantNew  bool
		check    string
		wantHas  bool
		checkOld string
	}

	tests := []struct {
		name  string
		steps []step
	}{
		{
			name: "insert and reinsert",
			steps: []step{
				{add: "a", wantNew: true, check: "a", wantHas: true},
				{add: "a", wantNew: false, check: "a", wantHas: true},
				{add: "b", wantNew: true, check: "b", wantHas: true, checkOld: "a"},
			},
		},
		{
			name: "empty string is valid key",
			steps: []step{
				{add: "", wantNew: true, check: "", wantHas: true},
				{add: "", wantNew: false, check: "", wantHas: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSet[string]()
			for i, st := range tt.steps {
				if got := s.Add(st.add); got != st.wantNew {
					t.Fatalf("step %d: Add(%q)=%v want %v", i, st.add, got, st.wantNew)
				}
				if got := s.Has(st.check); got != st.wantHas {
					t.Fatalf("step %d: Has(%q)=%v want %v", i, st.check, got, st.wantHas)
				}
				if st.checkOld != "" && !s.Has(st.checkOld) {
					t.Fatalf("step %d: expected %q to remain present", i, st.checkOld)
				}
			}
		})
	}
}

func TestSet_All(t *testing.T) {
	t.Parallel()

	s := NewSet("c", "a", "b", "a")
	var got []string
	for v := range s.All() {
		got = append(got, v)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("All()=%v want %v", got, []string{"a", "b", "c"})
	}
}

func TestSet_Nil(t *testing.T) {
	t.Parallel()

	var s Set[string]
	if s.Has("x") {
		t.Fatalf("Has() on nil set returned true")
	}
	if got := s.Slice(); len(got) != 0 {
		t.Fatalf("Slice() on nil set=%v want empty", got)
	}

	var got []string
	for v := range s.All() {
		got = append(got, v)
	}
	if len(got) != 0 {
		t.Fatalf("All() on nil set=%v want empty", got)
	}
}

func TestNormalizeLower(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "  ", want: ""},
		{in: "Hello", want: "hello"},
		{in: "  HELLO  ", want: "hello"},
		{in: "  Go Lang  ", want: "go lang"},
		{in: "npm", want: "npm"},
		{in: "\tPyPI\n", want: "pypi"},
	}

	for _, tt := range tests {
		if got := NormalizeLower(tt.in); got != tt.want {
			t.Errorf("NormalizeLower(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}
