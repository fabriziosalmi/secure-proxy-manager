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
		// A comment after an entry is not the entry. The last field used to
		// be taken, so these StevenBlack and Dan Pollock lines blocked
		// github.com and the sites their comments named.
		{"0.0.0.0 docs.pipenv.org # https://github.com/StevenBlack/hosts/issues/1635", Domain, "docs.pipenv.org", Accepted},
		{"127.0.0.1 ad.example.net #[see www.wired.com]", Domain, "ad.example.net", Accepted},
		{"0.0.0.0 tracker.example\t# tab before the comment", Domain, "tracker.example", Accepted},
		{"evil.example # plain list with a reason", Domain, "evil.example", Accepted},
		{"evil.example ; semicolon comment", Domain, "evil.example", Accepted},
		{":: v6-hosts.example", Domain, "v6-hosts.example", Accepted},
		{"::1 localhost ip6-localhost ip6-loopback", Domain, "", Invalid},
		// A # with no space before it belongs to the entry: a URL fragment.
		{"https://evil.example/#frag", Domain, "evil.example", Accepted},
		// IP feeds annotate too (Spamhaus DROP: "net ; SBL id").
		{"198.51.100.0/24 ; SBL123456", IP, "198.51.100.0/24", Accepted},
		{"203.0.113.9 # seen 2026-11-01", IP, "203.0.113.9", Accepted},
		{"203.0.113.9\t1\t# ipsum count", IP, "203.0.113.9", Accepted},
		// Adblock syntax, as AdGuard Home and Pi-hole lists publish it.
		{"[Adblock Plus]", Domain, "", Ignored},
		{"[Adblock Plus 2.0]", Domain, "", Ignored},
		{"! Title: HaGeZi's Multi PRO", Domain, "", Ignored},
		{"||telemetry.001-studio.com^", Domain, "telemetry.001-studio.com", Accepted},
		{"||ads.example^$important", Domain, "ads.example", Accepted},
		{"||ads.example^ # a comment", Domain, "ads.example", Accepted},
		// An exception allows; a path, a wildcard or another modifier blocks
		// less than the whole name: none is taken.
		{"@@||allowed.example^", Domain, "", Invalid},
		{"||ads.example/banner^", Domain, "", Invalid},
		{"||ads.*.example^", Domain, "", Invalid},
		{"||ads.example^$third-party", Domain, "", Invalid},
		{"||ads.example", Domain, "", Invalid},
		{"||^", Domain, "", Invalid},
		{"||198.51.100.7^", IP, "", Invalid},
	} {
		if e, v := Parse(c.line, c.kind); e != c.entry || v != c.v {
			t.Errorf("Parse(%q, %s) = %q, %d; want %q, %d", c.line, c.kind, e, v, c.entry, c.v)
		}
	}
}
