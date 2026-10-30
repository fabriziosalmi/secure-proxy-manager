package engine

import "testing"

// SHELL-009 names offensive tooling. It must not fire on the ordinary word
// "beacon" in a host or a path, which it did on real traffic and on
// the benign datasets wafeval measures.
func TestShell009(t *testing.T) {
	e := New(Config{BlockThreshold: 10})
	fired := func(s string) bool {
		ms, _ := e.MatchRulesScored(NormalizeInput(s))
		for _, m := range ms {
			if m.RuleID == "SHELL-009" {
				return true
			}
		}
		return false
	}
	for _, s := range []string{
		"//beacon.viafoura.io:443",
		"https://www.balonnebeacon.com.au/",
		"http://news.example.com/the-beacon-of-hope",
		"//beaconlbrowser.com:443",
	} {
		if fired(s) {
			t.Errorf("SHELL-009 fired on %q", s)
		}
	}
	for _, s := range []string{
		"http://x.example/dl?f=mimikatz.exe",
		"http://x.example/a?cmd=Invoke-Mimikatz",
		"http://x.example/tools/metasploit/payload",
		"http://x.example/p?q=CobaltStrike%20teamserver",
	} {
		if !fired(s) {
			t.Errorf("SHELL-009 missed %q", s)
		}
	}
}
