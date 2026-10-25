package database

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// exportedNames runs the export and returns what Squid's source list and the
// dnsmasq hosts file hold.
func exportedNames(t *testing.T, blocked, allowed []string) (squid, hosts []string, onAllowed int) {
	t.Helper()
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Init(db, "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	for _, d := range blocked {
		if _, err := db.Exec("INSERT INTO domain_blacklist(domain) VALUES(?)", d); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range allowed {
		if _, err := db.Exec("INSERT INTO domain_whitelist(domain, type) VALUES(?, 'fqdn')", d); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(dir, "config")
	if err := ExportBlacklistsToFiles(db, cfg); err != nil {
		t.Fatal(err)
	}
	read := func(p string) []string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Fields(string(b))
	}
	squid = read(filepath.Join(cfg, "domain_blacklist.txt"))
	for _, f := range read(filepath.Join(cfg, "dnsmasq.d", "blocklist.hosts")) {
		if f != "0.0.0.0" && f != "::" {
			hosts = append(hosts, f)
		}
	}
	sort.Strings(squid)
	sort.Strings(hosts)
	onAllowed, err = BlockedOnAllowed(db)
	if err != nil {
		t.Fatal(err)
	}
	return squid, hosts, onAllowed
}

// An allowed name takes a blocked entry off both enforcement files whenever
// the two enforce the same name: "*.x" and ".x" are enforced as x, in any
// case. Before, only the identical string was taken out, so an allowed
// star.example left "*.star.example" blocked in dnsmasq and in Squid while
// the page said an allowed name takes the identical name off Blocked domains.
func TestAllowedNameTakesOffEveryFormOfTheBlockedName(t *testing.T) {
	blocked := []string{"plain.example", "*.star.example", ".dot.example", "*..dd.example", "Mixed.Case.example", "*.Mixed.Star.example",
		"www.plain.example", "kept.example"}
	allowed := []string{"plain.example", "star.example", "dot.example", "dd.example", "mixed.case.example", "Mixed.Star.example"}
	squid, hosts, onAllowed := exportedNames(t, blocked, allowed)
	if want := []string{"kept.example", "www.plain.example"}; strings.Join(squid, " ") != strings.Join(want, " ") {
		t.Errorf("domain_blacklist.txt = %v, want %v (an allowed name covers no subdomain)", squid, want)
	}
	if want := []string{"kept.example", "kept.example", "www.plain.example", "www.plain.example"}; strings.Join(hosts, " ") != strings.Join(want, " ") {
		t.Errorf("blocklist.hosts names = %v, want %v", hosts, want)
	}
	if onAllowed != 6 {
		t.Errorf("BlockedOnAllowed = %d, want 6, the entries the export left out", onAllowed)
	}
}

// dnsmasq answers an exact hosts name, and the name it must answer for
// ".dot.example" is dot.example, the one Squid blocks. Measured with the dns
// image (dnsmasq 2.92): a hosts line "0.0.0.0 .dot.example" is read and
// answers no query, so the entry was enforced by Squid and not by the sinkhole.
func TestHostsFileHoldsTheNameSquidEnforces(t *testing.T) {
	_, hosts, _ := exportedNames(t, []string{".dot.example", "*.star.example", "UPPER.example"}, nil)
	want := []string{"dot.example", "dot.example", "star.example", "star.example", "upper.example", "upper.example"}
	if strings.Join(hosts, " ") != strings.Join(want, " ") {
		t.Errorf("blocklist.hosts names = %v, want %v", hosts, want)
	}
}

func TestEnforcedDomain(t *testing.T) {
	for in, want := range map[string]string{
		"example.com": "example.com", "*.example.com": "example.com", ".example.com": "example.com",
		"..example.com": "example.com", "Example.COM": "example.com", "*.Ads.Example.com": "ads.example.com",
		"ads.*.example": "ads.*.example",
	} {
		if got := EnforcedDomain(in); got != want {
			t.Errorf("EnforcedDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
