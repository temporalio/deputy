package forge

import "testing"

func TestSplitOwnerRepo(t *testing.T) {
	tests := []struct {
		name      string
		wantOwner string
		wantRepo  string
	}{
		{"actions/checkout", "actions", "checkout"},
		{"github/codeql-action", "github", "codeql-action"},
		{"temporalio/deputy/actions/setup", "temporalio", "deputy"},
		{"github.com/temporalio/deputy", "temporalio", "deputy"},
		{"/owner/repo/", "owner", "repo"},
		{"singlename", "", ""},
		{"", "", ""},
	}
	for _, tc := range tests {
		owner, repo := SplitOwnerRepo(tc.name)
		if owner != tc.wantOwner || repo != tc.wantRepo {
			t.Errorf("SplitOwnerRepo(%q) = (%q, %q), want (%q, %q)",
				tc.name, owner, repo, tc.wantOwner, tc.wantRepo)
		}
	}
}

func TestSplitOwnerRepoRest(t *testing.T) {
	owner, repo, rest := SplitOwnerRepoRest("temporalio/deputy/actions/setup")
	if owner != "temporalio" || repo != "deputy" || rest != "actions/setup" {
		t.Errorf("SplitOwnerRepoRest = (%q, %q, %q), want (temporalio, deputy, actions/setup)", owner, repo, rest)
	}
	if _, _, rest := SplitOwnerRepoRest("actions/checkout"); rest != "" {
		t.Errorf("expected empty rest for owner/repo only, got %q", rest)
	}
}

func TestRepoSlugFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://github.com/temporalio/deputy.git", "temporalio/deputy"},
		{"https://github.com/temporalio/deputy", "temporalio/deputy"},
		{"git@github.com:temporalio/deputy.git", "temporalio/deputy"},
		{"ssh://git@github.com/temporalio/deputy.git", "temporalio/deputy"},
		{"https://gitlab.com/group/project.git", "group/project"},
		{"https://github.com/temporalio/deputy/tree/main", "temporalio/deputy"},
		{"", ""},
		{"not-a-url", ""},
		{"https://github.com/onlyowner", ""},
	}
	for _, tc := range tests {
		if got := RepoSlugFromURL(tc.url); got != tc.want {
			t.Errorf("RepoSlugFromURL(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}
