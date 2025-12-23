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

func TestNormalizeUpper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: "  ", want: ""},
		{in: "Hello", want: "HELLO"},
		{in: "  hello  ", want: "HELLO"},
		{in: "critical", want: "CRITICAL"},
		{in: "  High  ", want: "HIGH"},
		{in: "\tmedium\n", want: "MEDIUM"},
	}

	for _, tt := range tests {
		if got := NormalizeUpper(tt.in); got != tt.want {
			t.Errorf("NormalizeUpper(%q)=%q want %q", tt.in, got, tt.want)
		}
	}
}

func TestDedupe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "nil", in: nil, want: nil},
		{name: "empty", in: []string{}, want: nil},
		{name: "single", in: []string{"a"}, want: []string{"a"}},
		{name: "no_dupes", in: []string{"a", "b", "c"}, want: []string{"a", "b", "c"}},
		{name: "all_dupes", in: []string{"a", "a", "a"}, want: []string{"a"}},
		{name: "mixed", in: []string{"b", "a", "b", "c", "a"}, want: []string{"b", "a", "c"}},
		{name: "preserves_order", in: []string{"c", "b", "a", "b", "c"}, want: []string{"c", "b", "a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Dedupe(tt.in)
			if !slices.Equal(got, tt.want) {
				t.Errorf("Dedupe(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestDedupeFunc(t *testing.T) {
	t.Parallel()

	type item struct {
		id   int
		name string
	}

	tests := []struct {
		name string
		in   []item
		want []item
	}{
		{name: "nil", in: nil, want: nil},
		{name: "empty", in: []item{}, want: nil},
		{
			name: "by_id",
			in:   []item{{1, "a"}, {2, "b"}, {1, "c"}, {3, "d"}},
			want: []item{{1, "a"}, {2, "b"}, {3, "d"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DedupeFunc(tt.in, func(i item) int { return i.id })
			if !slices.Equal(got, tt.want) {
				t.Errorf("DedupeFunc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMerge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		slices [][]string
		want   []string
	}{
		{name: "nil", slices: nil, want: nil},
		{name: "empty", slices: [][]string{}, want: nil},
		{name: "single_empty", slices: [][]string{{}}, want: nil},
		{name: "single", slices: [][]string{{"a", "b"}}, want: []string{"a", "b"}},
		{
			name:   "two_slices",
			slices: [][]string{{"a", "b"}, {"b", "c"}},
			want:   []string{"a", "b", "c"},
		},
		{
			name:   "three_slices",
			slices: [][]string{{"a"}, {"b", "a"}, {"c", "b", "a"}},
			want:   []string{"a", "b", "c"},
		},
		{
			name:   "preserves_order",
			slices: [][]string{{"c", "b"}, {"a", "c"}},
			want:   []string{"c", "b", "a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Merge(tt.slices...)
			if !slices.Equal(got, tt.want) {
				t.Errorf("Merge() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		in        []int
		predicate func(int) bool
		want      []int
	}{
		{name: "nil", in: nil, predicate: func(i int) bool { return true }, want: nil},
		{name: "empty", in: []int{}, predicate: func(i int) bool { return true }, want: nil},
		{
			name:      "filter_even",
			in:        []int{1, 2, 3, 4, 2, 5, 4},
			predicate: func(i int) bool { return i%2 == 0 },
			want:      []int{2, 4},
		},
		{
			name:      "filter_positive",
			in:        []int{-1, 1, -2, 2, 1, -1},
			predicate: func(i int) bool { return i > 0 },
			want:      []int{1, 2},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Filter(tt.in, tt.predicate)
			if !slices.Equal(got, tt.want) {
				t.Errorf("Filter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSet_Len(t *testing.T) {
	t.Parallel()

	var nilSet Set[string]
	if nilSet.Len() != 0 {
		t.Errorf("nil set Len() = %d, want 0", nilSet.Len())
	}

	s := NewSet("a", "b", "c", "a")
	if s.Len() != 3 {
		t.Errorf("set Len() = %d, want 3", s.Len())
	}
}
