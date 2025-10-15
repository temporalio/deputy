package text

import "testing"

func TestTruncateEnd(t *testing.T) {
    cases := []struct{ s string; w int; want string }{
        {"hello", 10, "hello"},
        {"hello", 5, "hello"},
        {"hello", 4, "hel…"},
        {"", 3, ""},
    }
    for i, c := range cases {
        got := TruncateEnd(c.s, c.w)
        if got != c.want {
            t.Fatalf("case %d: got %q want %q", i, got, c.want)
        }
    }
}

func TestTruncateMiddle(t *testing.T) {
    cases := []struct{ s string; w int; want string }{
        {"abcdef", 6, "abcdef"},
        {"abcdef", 5, "ab…ef"},
        {"abcdef", 4, "a…ef"},
        {"abcdef", 3, "a…f"},
        {"abcdef", 2, "…f"},
        {"", 3, ""},
    }
    for i, c := range cases {
        got := TruncateMiddle(c.s, c.w)
        if got != c.want {
            t.Fatalf("case %d: got %q want %q", i, got, c.want)
        }
    }
}
