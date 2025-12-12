package output

import (
	"bytes"
	"testing"
)

func TestDocRender_NewlineTermination(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  Doc
		want string
	}{
		{
			name: "empty doc",
			doc:  Doc{},
			want: "",
		},
		{
			name: "single line",
			doc:  Doc{Lines: []Line{{{Text: "hello"}}}},
			want: "hello\n",
		},
		{
			name: "leading blank line",
			doc:  Doc{Lines: []Line{nil, {{Text: "hello"}}}},
			want: "\nhello\n",
		},
		{
			name: "multiple lines",
			doc:  Doc{Lines: []Line{{{Text: "a"}}, {{Text: "b"}}}},
			want: "a\nb\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := tc.doc.Render(&buf, PlainStyles()); err != nil {
				t.Fatalf("Render: %v", err)
			}
			if got := buf.String(); got != tc.want {
				t.Fatalf("Render() = %q, want %q", got, tc.want)
			}
		})
	}
}
