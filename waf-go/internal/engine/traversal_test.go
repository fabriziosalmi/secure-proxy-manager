package engine

import "testing"

// The traversal rules read a step up with either separator, a run of
// separators, "./" between the steps or more than two dots, a sensitive file
// under etc with either separator, and a drive letter before a directory an
// attack reads on Windows; a single relative step and an upload's
// C:\fakepath stay allowed.
func TestTraversalShapes(t *testing.T) {
	e := New(Config{BlockThreshold: 10})
	for _, attack := range []string{
		"f=..//..//..//etc/x", `f=..\\\..\\\..\\\x`, `f=...\...\...\x`, "f=....//....//x",
		`f=../\../\x`, "f=.//..//.//..//x", `f=..\/..\/x`,
		`f=..\etc\issue`, "f=../etc/issue", `f=\\\../etc\\\passwd`, "f=/etc/hostname.hme0", "f=/etc/os-release",
		`f=..\/..\/windows\/system32\/drivers\/etc\/hosts`,
		"f=C:/users/administrator/desktop/desktop.ini", `f=C:\xampp\apache\logs\error_log`,
		`f=c:\inetpub\wwwroot\web.config`, `f=C:\Windows\win.ini`, `f=D:\wamp\www\config.php`,
	} {
		ms, score := e.MatchRulesScored(NormalizeInput(attack))
		if score < 10 || !hasCategory(ms, "DIRECTORY_TRAVERSAL") {
			t.Errorf("%q: score %d, %v", attack, score, ids(ms))
		}
	}
	for _, benign := range []string{
		"../img/logo.png", "./../style.css", `file=C:\fakepath\photo.jpg`,
		`path=C:\Users\alice\Documents\report.pdf`, `dir=D:\Program Files\App`,
		"q=wait.../then", "v=1.2..3", "/static/etc.js", "/catalog/etc-and-more/",
	} {
		if ms, _ := e.MatchRulesScored(NormalizeInput(benign)); hasCategory(ms, "DIRECTORY_TRAVERSAL") {
			t.Errorf("benign %q: %v", benign, ids(ms))
		}
	}
}
