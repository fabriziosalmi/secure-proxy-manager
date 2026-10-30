package crs

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

func req(t *testing.T, raw string) *http.Request {
	t.Helper()
	r, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func newPL1(t *testing.T) *Engine {
	t.Helper()
	e, err := New(Options{Paranoia: 1})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// A configuration that does not compile is an error, not an engine.
func TestNewRefusesWhatDoesNotLoad(t *testing.T) {
	for _, p := range []int{0, 5} {
		if _, err := New(Options{Paranoia: p}); err == nil {
			t.Errorf("paranoia %d accepted", p)
		}
	}
	_, err := New(Options{Paranoia: 1, extra: "SecRule ARGS \"@rx (\" \"id:1999999,phase:2,deny\"\n"})
	if err == nil || !strings.Contains(err.Error(), "loading the OWASP Core Rule Set") {
		t.Errorf("a broken rule loaded: %v", err)
	}
}

func TestInspect(t *testing.T) {
	e := newPL1(t)
	form := "user=admin&pass=1%27%20UNION%20SELECT%20password%20FROM%20users--"
	sqli := req(t, "POST http://shop.example/login HTTP/1.1\r\nHost: shop.example\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: "+
		itoa(len(form))+"\r\n\r\n"+form)
	res := e.Inspect(sqli, []byte(form), "192.0.2.1", true)
	if !res.Blocked || res.Score < 5 || !strings.HasPrefix(strings.Join(res.Rules, ","), "942") || len(res.Explain) == 0 {
		t.Errorf("SQL injection in a form: %+v", res)
	}
	if got := Categories(res.Rules); got[0] != "CRS_SQLI" {
		t.Errorf("categories %v, want CRS_SQLI first", got)
	}

	benign := req(t, "GET http://shop.example/item?id=7&lang=it HTTP/1.1\r\nHost: shop.example\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n")
	if res := e.Inspect(benign, nil, "192.0.2.1", true); res.Blocked || res.Score != 0 || len(res.Explain) != 0 {
		t.Errorf("benign GET: %+v", res)
	}
}

// 920440 runs on the egress list: backup and temporary copies are refused,
// what a client legitimately downloads is not.
func TestRestrictedExtensionsForEgress(t *testing.T) {
	e := newPL1(t)
	for path, want := range map[string]bool{
		"/site/config.php.bak": true, "/db/dump.old": true, "/inc/header.inc": true,
		"/ca/intermediate.crt": false, "/symbols/app.pdb": false, "/install.sh": false, "/data/geo.dat": false,
	} {
		r := req(t, "GET http://files.example"+path+" HTTP/1.1\r\nHost: files.example\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")
		if got := e.Inspect(r, nil, "192.0.2.1", false).Blocked; got != want {
			t.Errorf("%s: blocked=%v want %v", path, got, want)
		}
	}
}

// Cloudflare's image resizing takes its options in the path, and
// onerror=redirect is one of them: 941120 reads it as an event handler. The
// path is let through 941120 under /cdn-cgi/image/ only; the same option
// anywhere else, or in an argument, still blocks.
func TestCloudflareImageOptions(t *testing.T) {
	e := newPL1(t)
	for target, want := range map[string]bool{
		"/cdn-cgi/image/width=640,onerror=redirect,format=auto/img/a.jpg":     false,
		"/cdn-cgi/image/onerror=redirect,width=640/https://cdn.example/a.jpg": false,
		"/images/width=640,onerror=redirect/a.jpg":                            true,
		"/cdn-cgi/image/width=640/a.jpg?x=%22%20onerror=alert(1)":             true,
		"/cdn-cgi/image/width=640/a.jpg?x=%3Cscript%3Ealert(1)%3C/script%3E":  true,
	} {
		r := req(t, "GET http://img.example"+target+" HTTP/1.1\r\nHost: img.example\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")
		if got := e.Inspect(r, nil, "192.0.2.1", false); got.Blocked != want {
			t.Errorf("%s: blocked=%v want %v %v", target, got.Blocked, want, got.Rules)
		}
	}
	keep, err := New(Options{Paranoia: 1, KeepPolicy: true})
	if err != nil {
		t.Fatal(err)
	}
	r := req(t, "GET http://img.example/cdn-cgi/image/width=640,onerror=redirect/a.jpg HTTP/1.1\r\nHost: img.example\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")
	if res := keep.Inspect(r, nil, "192.0.2.1", false); !res.Blocked || !strings.Contains(strings.Join(res.Rules, ","), "941120") {
		t.Errorf("CRS as shipped no longer flags the option: %+v", res)
	}
}

// Framing that net/http keeps outside the header map is given back to CRS.
func TestInspectSeesFraming(t *testing.T) {
	e := newPL1(t)
	chunked := req(t, "POST http://api.example/x HTTP/1.1\r\nHost: api.example\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n")
	if res := e.Inspect(chunked, []byte("{}"), "192.0.2.1", false); strings.Contains(strings.Join(res.Rules, ","), "920180") {
		t.Errorf("chunked POST scored 920180: %v", res.Rules)
	}
	// Built by hand, with the length in the field and not in the header.
	r := req(t, "POST http://api.example/x HTTP/1.1\r\nHost: api.example\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
	r.Header.Del("Content-Length")
	if res := e.Inspect(r, []byte("{}"), "192.0.2.1", false); strings.Contains(strings.Join(res.Rules, ","), "920180") {
		t.Errorf("POST with ContentLength set scored 920180: %v", res.Rules)
	}
}

func TestCategories(t *testing.T) {
	got := strings.Join(Categories([]string{"942100", "941100", "942200", "200002", "913100"}), ",")
	if got != "CRS_SQLI,CRS_XSS,CRS,CRS_SCANNER" {
		t.Errorf("got %s", got)
	}
}

// The ablation options rewrite the removals and the extension list, and
// nothing else.
func TestDirectivesOptions(t *testing.T) {
	d := directives(Options{Paranoia: 1})
	if !strings.Contains(d, "SecRuleRemoveById 920420 920450 920451 920480 943110 943120 930130 932370\n") || !strings.Contains(d, "id:900240") {
		t.Error("the default directives lack the removals or the egress extensions")
	}
	d = directives(Options{Paranoia: 2, Restore: map[string]bool{"932370": true, "920420": true}})
	if !strings.Contains(d, "SecRuleRemoveById 920450 920451 920480 943110 943120 930130\n") || !strings.Contains(d, "blocking_paranoia_level=2") {
		t.Error("Restore did not take the two IDs out of the removals")
	}
	all := map[string]bool{}
	for _, id := range strings.Fields("920420 920450 920451 920480 943110 943120 930130 932370") {
		all[id] = true
	}
	if d = directives(Options{Paranoia: 1, Restore: all}); strings.Contains(d, "SecRuleRemoveById") || !strings.Contains(d, "SecRuleUpdateTargetById 942100") {
		t.Error("restoring every ID should leave the 942100 exclusion alone")
	}
	if d = directives(Options{Paranoia: 1, KeepPolicy: true}); strings.Contains(d, "SecRuleRemoveById") || strings.Contains(d, "id:900240") || strings.Contains(d, "942100") || strings.Contains(d, "cdn-cgi") {
		t.Error("KeepPolicy kept an adjustment")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
