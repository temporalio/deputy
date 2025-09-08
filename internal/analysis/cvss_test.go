package analysis

import "testing"

func Test_ParseCVSSScore_and_parseFloat(t *testing.T) {
    tests := []struct{ in string; want float64 }{
        {"3", 3},
        {"7.5", 7.5},
        {"7.5-something", 7.5},
        {"11.1", -1},
        {"abc", -1},
        {"CVSS:3.1/Base:9.8/AV:N/AC:L", 9.8},
        {"HIGH", 7.5},
        {"no-score", -1},
    }
    for _, tt := range tests {
        got := ParseCVSSScore(tt.in)
        if got != tt.want {
            t.Fatalf("ParseCVSSScore(%q)=%v want %v", tt.in, got, tt.want)
        }
    }
}

