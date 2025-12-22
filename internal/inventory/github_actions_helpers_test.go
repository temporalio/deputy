package inventory

import "testing"

func TestShouldIncludeGitHubActions_Table(t *testing.T) {
	tests := []struct {
		names []string
		want  bool
	}{
		{nil, true}, // nil means "all ecosystems"
		{[]string{}, false},
		{[]string{"go"}, false},
		{[]string{"github-actions"}, true},
		{[]string{"actions"}, true},
		{[]string{"gha"}, true},
		{[]string{"npm", "go", "github"}, true},
	}
	for _, tc := range tests {
		label := "nil"
		if tc.names != nil {
			if len(tc.names) == 0 {
				label = "empty"
			} else {
				label = tc.names[0]
				if len(tc.names) > 1 {
					label = tc.names[0] + "+..."
				}
			}
		}
		t.Run(label, func(t *testing.T) {
			if got := shouldIncludeGitHubActions(tc.names); got != tc.want {
				t.Fatalf("shouldIncludeGitHubActions(%v) = %v, want %v", tc.names, got, tc.want)
			}
		})
	}
}

func TestFilterExternalEcosystems_Table(t *testing.T) {
	tests := []struct {
		in   []string
		want []string
	}{
		{nil, nil},
		{[]string{}, nil},
		{[]string{"github-actions"}, nil},
		{[]string{"go", "github-actions", "npm"}, []string{"go", "npm"}},
		{[]string{"actions", "gha", "ruby"}, []string{"ruby"}},
	}
	for _, tc := range tests {
		label := "nil"
		if len(tc.in) > 0 {
			label = tc.in[0]
		}
		t.Run(label, func(t *testing.T) {
			got := filterExternalEcosystems(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("filterExternalEcosystems(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("filterExternalEcosystems(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}
