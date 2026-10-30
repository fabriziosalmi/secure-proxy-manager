package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A corpus whose outcome is known line by line.
const miniCorpus = `{"id":"a1","source":"t","label":"attack","category":"sqli","context":"bump","method":"GET","url":"http://shop.example.com/p?id=1%27%20UNION%20SELECT%20password%20FROM%20users--","headers":[],"body":""}
{"id":"a2","source":"t","label":"attack","category":"xss","context":"bump","method":"GET","url":"http://shop.example.com/s?q=<script>alert(1)</script>","headers":[],"body":""}
{"id":"b1","source":"t","label":"benign","category":"normal","context":"bump","method":"GET","url":"http://shop.example.com/index.html","headers":[["User-Agent","Mozilla/5.0"]],"body":""}
{"id":"b2","source":"t","label":"benign","category":"normal","context":"bump","method":"POST","url":"http://shop.example.com/form","headers":[["Content-Type","application/x-www-form-urlencoded"]],"body":"name=Ada&city=Genova"}
{"id":"t1","source":"t","label":"attack","category":"typo","context":"nobump","method":"CONNECT","url":"paypa1.com:443","headers":[],"body":""}
{"id":"n1","source":"t","label":"benign","category":"benign","context":"nobump","method":"CONNECT","url":"example.org:443","headers":[],"body":""}
{"id":"l1","source":"t","label":"benign","category":"lan","context":"bump","method":"GET","url":"http://192.168.1.10/admin","headers":[],"body":""}
{"id":"p1","source":"t","label":"attack","category":"broken","context":"bump","method":"GET","url":"http://shop.example.com/a b c","headers":[],"body":""}
`

func runOnce(t *testing.T, dir, name string) []byte {
	t.Helper()
	corpus := filepath.Join(dir, "mini.jsonl")
	if err := os.WriteFile(corpus, []byte(miniCorpus), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := newSPMEngine([]string{"waf_h_sequence"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rep := newReport(eng, "test", false)
	seq := 0
	if err := runFile(corpus, eng, rep, &seq, 0); err != nil {
		t.Fatal(err)
	}
	rep.finish()
	out := filepath.Join(dir, name)
	if err := writeJSON(out, rep); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReportIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	a, b := runOnce(t, dir, "a.json"), runOnce(t, dir, "b.json")
	if !bytes.Equal(a, b) {
		t.Fatal("two runs on the same corpus wrote different reports")
	}
}

func TestMiniCorpusCounts(t *testing.T) {
	var rep Report
	if err := json.Unmarshal(runOnce(t, t.TempDir(), "r.json"), &rep); err != nil {
		t.Fatal(err)
	}
	got := map[string]Cell{}
	for _, c := range rep.Summary {
		got[c.Context] = c
	}
	// bump: a1, a2 blocked (TP); b1, b2 allowed (TN); l1 is a LAN host,
	// allowed uninspected (TN, counted as skipped); p1 does not parse.
	if c := got["bump"]; c.TP != 2 || c.FN != 0 || c.FP != 0 || c.TN != 3 || c.LANSkipped != 1 || c.ParseErrors != 1 {
		t.Errorf("bump: %+v", c)
	}
	// nobump: the typosquat scores 5, under the threshold of 10, so it is a
	// false negative, and one that was observed; example.org is a TN.
	if c := got["nobump"]; c.TP != 0 || c.FN != 1 || c.TN != 1 || c.FP != 0 {
		t.Errorf("nobump: %+v", c)
	}
	if rep.FNObserved["t|nobump"] != 1 {
		t.Errorf("fn_observed = %v, want t|nobump: 1", rep.FNObserved)
	}
	if rep.Corpus[0].Records != 8 || len(rep.Corpus[0].SHA256) != 64 {
		t.Errorf("corpus entry %+v", rep.Corpus[0])
	}
}

// The Coraza adapter blocks a plain SQL injection and lets a benign GET and
// a CONNECT through: CONNECT is the whole of HTTPS without bump, so an
// adapter that refused it would measure nothing but its own mistake.
func TestCorazaAdapterBaseline(t *testing.T) {
	for _, pl := range []int{1, 2} {
		eng, err := newCorazaEngine(pl)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range []struct {
			rec  Record
			want bool
		}{
			{Record{Method: "GET", URL: "http://shop.example.com/p?id=1%27%20UNION%20SELECT%20password%20FROM%20users--", Headers: [][]string{{"User-Agent", "Mozilla/5.0"}, {"Accept", "text/html"}}}, true},
			{Record{Method: "GET", URL: "http://shop.example.com/index.html", Headers: [][]string{{"User-Agent", "Mozilla/5.0"}, {"Accept", "text/html"}}}, false},
			{Record{Method: "CONNECT", URL: "example.org:443"}, false},
			// 920440 is kept: an old or backup file is recon (CSIC).
			{Record{Method: "GET", URL: "http://shop.example.com/tienda1/index.jsp.bak", Headers: [][]string{{"User-Agent", "Mozilla/5.0"}, {"Accept", "text/html"}}}, true},
		} {
			r, err := buildRequest(&c.rec)
			if err != nil {
				t.Fatal(err)
			}
			if v := eng.Inspect(r, "192.0.2.10"); v.Blocked != c.want {
				t.Errorf("PL%d %s %s: blocked=%v want %v (rules %v)", pl, c.rec.Method, c.rec.URL, v.Blocked, c.want, v.Rules)
			}
		}
	}

	// navigator.sendBeacon posts text/plain; on an egress proxy the
	// destination decides what it accepts, so the policy rules are removed
	// and PL1 lets it through. PL2 still blocks this JSON-in-text/plain body
	// on five SQLi rules (942200 942340 942370 942430 942520): CRS does not
	// parse it as JSON. That is PL2's own false positive, not the adapter's.
	pl1, err := newCorazaEngine(1)
	if err != nil {
		t.Fatal(err)
	}
	beacon := Record{Method: "POST", URL: "http://stats.example.com/collect",
		Headers: [][]string{{"User-Agent", "Mozilla/5.0"}, {"Accept", "*/*"}, {"Content-Type", "text/plain;charset=UTF-8"}},
		Body:    `{"event":"pageview","path":"/"}`}
	r, err := buildRequest(&beacon)
	if err != nil {
		t.Fatal(err)
	}
	if v := pl1.Inspect(r, "192.0.2.10"); v.Blocked {
		t.Errorf("PL1 blocked a text/plain beacon (rules %v)", v.Rules)
	}

	// A pasted multi-line text (an issue report) uploaded as text/plain, and
	// a page request carrying the CCPA string us_privacy=1---.
	for _, rec := range []Record{
		{Method: "POST", URL: "https://paste.example.com/api/documents",
			Headers: [][]string{{"User-Agent", "Mozilla/5.0"}, {"Accept", "*/*"}, {"Content-Type", "text/plain; charset=utf-8"}},
			Body:    "Steps to reproduce:\n1. set session_id to 1ec\n2. run the deploy\nExpected: green build"},
		{Method: "POST", URL: "https://paste.example.com/api/documents",
			Headers: [][]string{{"User-Agent", "Mozilla/5.0"}, {"Accept", "*/*"}, {"Content-Type", "text/plain"}},
			Body:    "10.5.6.7 - svc [11/jun/2026:16:00:00 +0000] \"POST /webhook/github HTTP/1.1\" 200 0 \"-\"\n172.18.4.21 - - [18/jun/2026:09:14:02 +0000] \"GET /auth/callback HTTP/1.1\" 302 0\n"},
		{Method: "GET", URL: "https://news.example.com/article?id=42&us_privacy=1---",
			Headers: [][]string{{"User-Agent", "Mozilla/5.0"}, {"Accept", "text/html"}}},
		{Method: "GET", URL: "https://pixel.example.com/p?usp=1---&sst.us_privacy=1---&AV_CCPA=1---&uspstring=1---&uspConsent=1---&usps=1---",
			Headers: [][]string{{"User-Agent", "Mozilla/5.0"}, {"Accept", "image/*"}}},
		{Method: "GET", URL: "https://shop.example.com/cart?session_id=8f2a91c4",
			Headers: [][]string{{"User-Agent", "Mozilla/5.0"}, {"Accept", "text/html"}, {"Referer", "https://www.othersite.example/"}}},
		{Method: "GET", URL: "https://cdn.example.com/config/site.example.com/config.json",
			Headers: [][]string{{"User-Agent", "Mozilla/5.0"}, {"Accept", "*/*"}}},
		{Method: "GET", URL: "https://sync.example.com/setuid?redir=https%3A%2F%2Fad.example%2Fx%3Fxuid%3D%24%7BCRITEO_USER_ID%7D%26puid%3D%24%7Bpubmatic_uid%7D",
			Headers: [][]string{{"User-Agent", "Mozilla/5.0"}, {"Accept", "image/*"}}},
	} {
		r, err := buildRequest(&rec)
		if err != nil {
			t.Fatal(err)
		}
		if v := pl1.Inspect(r, "192.0.2.10"); v.Blocked {
			t.Errorf("PL1 blocked %s %s (rules %v)", rec.Method, rec.URL, v.Rules)
		}
	}
}

// 920440 runs on the egress list: a backup, temporary or server-side file is
// recon (CSIC's .old, .inc, .bak, .htr, .cnf), while files clients download
// on their own (a CA's intermediate certificate, a debug symbol, an install
// script, a domain name in the path) pass.
func TestRestrictedExtensionsEgress(t *testing.T) {
	eng, err := newCorazaEngine(1)
	if err != nil {
		t.Fatal(err)
	}
	h := [][]string{{"User-Agent", "Mozilla/5.0"}, {"Accept", "*/*"}}
	for _, c := range []struct {
		url  string
		want bool
	}{
		{"http://shop.example.com/tienda1/index.jsp.old", true},
		{"http://shop.example.com/tienda1/global.inc", true},
		{"http://shop.example.com/tienda1/index.jsp.bak", true},
		{"http://shop.example.com/scripts/x.htr", true},
		{"http://shop.example.com/etc/my.cnf", true},
		{"http://shop.example.com/index.php.swp", true},
		{"http://shop.example.com/web.config", true},
		{"http://crt.sectigo.com/SectigoRSADomainValidationSecureServerCA.crt", false},
		{"http://cacerts.example.com/IntermediateCA.cer", false},
		{"https://letsencrypt.org/certs/isrgrootx1.pem", false},
		{"https://msdl.microsoft.com/download/symbols/ntdll.pdb/ABC123/ntdll.pdb", false},
		{"https://msdl.microsoft.com/download/symbols/ntdll.dll/5F1A2B3C1f0000/ntdll.dll", false},
		{"https://raw.githubusercontent.com/org/repo/main/install.sh", false},
		{"https://www.afternic.com/forsale/vendedorhinode.com?utm_source=x", false},
		{"http://www.findsounds.com/isapi/search.dll?keywords=modem", false},
		{"https://github.com/org/repo/releases/download/v1/geosite.dat", false},
	} {
		r, err := buildRequest(&Record{Method: "GET", URL: c.url, Headers: h})
		if err != nil {
			t.Fatal(err)
		}
		if v := eng.Inspect(r, "192.0.2.10"); v.Blocked != c.want {
			t.Errorf("%s: blocked=%v want %v (rules %v)", c.url, v.Blocked, c.want, v.Rules)
		}
	}
}

// The hybrid blocks what either half blocks: an SSRF to the metadata address
// (the spm half), a SQL injection in a form body (the CRS half, which reads
// the body after the spm half has), and lets benign requests and a CONNECT
// through.
func TestHybridEngine(t *testing.T) {
	eng, err := newHybridEngine([]string{"waf_h_sequence"}, hybridDefaultOff, nil)
	if err != nil {
		t.Fatal(err)
	}
	ua := []string{"User-Agent", "Mozilla/5.0"}
	acc := []string{"Accept", "text/html"}
	form := []string{"Content-Type", "application/x-www-form-urlencoded"}
	for _, c := range []struct {
		name string
		rec  Record
		want bool
	}{
		{"ssrf", Record{Method: "GET", URL: "http://shop.example.com/fetch?u=http://169.254.169.254/latest/meta-data/", Headers: [][]string{ua, acc}}, true},
		{"sqli in body", Record{Method: "POST", URL: "http://shop.example.com/login", Headers: [][]string{ua, acc, form}, Body: "user=admin&pass=1%27%20UNION%20SELECT%20password%20FROM%20users--"}, true},
		{"benign form", Record{Method: "POST", URL: "http://shop.example.com/contact", Headers: [][]string{ua, acc, form}, Body: "name=Ada&city=Genova"}, false},
		{"connect", Record{Method: "CONNECT", URL: "example.org:443"}, false},
	} {
		r, err := buildRequest(&c.rec)
		if err != nil {
			t.Fatal(err)
		}
		if v := eng.Inspect(r, "192.0.2.10"); v.Blocked != c.want {
			t.Errorf("%s: blocked=%v want %v (rules %v)", c.name, v.Blocked, c.want, v.Rules)
		}
	}
}

// Responses go through inspect.EvaluateResponse: a leaked private key and a
// reflected script are blocked, a plain page is not, a compressed text
// body is counted as uninspectable, and CRS alone reports that it does not
// inspect responses rather than passing them as clean.
func TestResponses(t *testing.T) {
	recs := []Record{
		{Kind: "response", Status: 200, Headers: [][]string{{"Content-Type", "text/plain"}}, Body: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAmockkeymockkeymockkeymockkeymockkeymockkey\n-----END RSA PRIVATE KEY-----"},
		{Kind: "response", Status: 200, Headers: [][]string{{"Content-Type", "text/html"}}, Body: "<html><body><script>alert(1)</script></body></html>"},
		{Kind: "response", Status: 200, Headers: [][]string{{"Content-Type", "text/html"}}, Body: "<html><body><p>Opening hours: 9 to 17.</p></body></html>"},
		{Kind: "response", Status: 200, Headers: [][]string{{"Content-Type", "text/html"}, {"Content-Encoding", "br"}}, Body: "\x1b\x0b\x00\xf8"},
	}
	spm, err := newSPMEngine([]string{"waf_h_sequence"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	crs, err := newCorazaEngine(1)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct{ blocked, uninspectable bool }{{true, false}, {true, false}, {false, false}, {false, true}}
	for i, rec := range recs {
		resp, err := buildResponse(&rec)
		if err != nil {
			t.Fatal(err)
		}
		v := spm.InspectResponse(resp)
		if v.Blocked != want[i].blocked || v.Uninspectable != want[i].uninspectable {
			t.Errorf("spm response %d: blocked=%v uninspectable=%v, want %+v (rules %v)", i, v.Blocked, v.Uninspectable, want[i], v.Rules)
		}
		resp, _ = buildResponse(&rec)
		if c := crs.InspectResponse(resp); !c.NotInspected || c.Blocked {
			t.Errorf("crs response %d: %+v, want NotInspected", i, c)
		}
	}
}

// A response record is counted as a response: a leaked key is a TP, a plain
// page a TN, and neither is parsed as a request.
func TestReportCountsResponses(t *testing.T) {
	dir := t.TempDir()
	corpus := filepath.Join(dir, "resp.jsonl")
	lines := `{"id":"k","source":"r","label":"attack","category":"key","context":"bump","kind":"response","status":200,"headers":[["Content-Type","text/plain"]],"body":"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAmockkeymockkey\n-----END RSA PRIVATE KEY-----"}
{"id":"p","source":"r","label":"benign","category":"page","context":"bump","kind":"response","status":200,"headers":[["Content-Type","text/html"]],"body":"<p>hello</p>"}
`
	if err := os.WriteFile(corpus, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := newSPMEngine([]string{"waf_h_sequence"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	rep := newReport(eng, "test", false)
	seq := 0
	if err := runFile(corpus, eng, rep, &seq, 0); err != nil {
		t.Fatal(err)
	}
	rep.finish()
	if c := rep.Summary[0]; c.TP != 1 || c.TN != 1 || c.ParseErrors != 0 {
		t.Errorf("responses counted as %+v, want TP 1 TN 1", c)
	}
}
