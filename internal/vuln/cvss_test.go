package vuln

import "testing"

func Test_ParseCVSSScore_and_parseFloat(t *testing.T) {
	tests := []struct {
		in   string
		want float64
	}{
		{in: "3", want: 3},
		{in: "7.5", want: 7.5},
		{in: "7.5-something", want: 7.5},
		{in: "11.1", want: -1},
		{in: "abc", want: -1},
		{in: "CVSS:3.1/Base:9.8/AV:N/AC:L", want: 9.8},
		{in: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N", want: 2.5},
		{in: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", want: 9.8},
		{in: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.8", want: 9.8},
		{in: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", want: 9.8},
		{in: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", want: 10.0},
		{in: "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", want: 1.0},
		{in: "AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N", want: 1.0},
		{in: "HIGH", want: 7.5},
		{in: "no-score", want: -1},
	}
	for _, test := range tests {
		got := ParseCVSSScore(test.in)
		if got != test.want {
			t.Fatalf("ParseCVSSScore(%q)=%v want %v", test.in, got, test.want)
		}
	}
}
