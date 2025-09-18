package gitutil

import "testing"

func Test_ParseTimeShorthandToISO_units(t *testing.T) {
	cases := []string{
		"1.second.ago",
		"2.minute.ago",
		"3.hour.ago",
		"1.day.ago",
		"2.week.ago",
		"1.month.ago",
		"1.year.ago",
	}
	for _, in := range cases {
		if iso := ParseTimeShorthandToISO(in); iso == "" {
			// month/year may not always parse? they should—fail if empty.
			t.Fatalf("expected timestamp for %s", in)
		}
	}
}
