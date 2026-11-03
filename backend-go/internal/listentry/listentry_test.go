package listentry

import "testing"

func TestParse(t *testing.T) {
	for _, c := range []struct {
		line  string
		kind  Kind
		entry string
		v     Verdict
	}{
		{"", Domain, "", Ignored},
		{"   # comment", Domain, "", Ignored},
		{"; comment", IP, "", Ignored},
		{"0.0.0.0 evil.example", Domain, "evil.example", Accepted},
		{"https://tracker.test/path?x=1", Domain, "tracker.test", Accepted},
		{"http://a.example:8080/", Domain, "a.example", Accepted},
		{".leading.example", Domain, "", Invalid},
		{"trailing.example.", Domain, "", Invalid},
		{"localhost", Domain, "", Invalid},
		{"<html>", Domain, "", Invalid},
		{"203.0.113.7", IP, "203.0.113.7", Accepted},
		{"198.51.100.0/24", IP, "198.51.100.0/24", Accepted},
		{"10.0.0.1", IP, "", Bogon},
		{"notanip", IP, "", Invalid},
	} {
		if e, v := Parse(c.line, c.kind); e != c.entry || v != c.v {
			t.Errorf("Parse(%q, %s) = %q, %d; want %q, %d", c.line, c.kind, e, v, c.entry, c.v)
		}
	}
}
