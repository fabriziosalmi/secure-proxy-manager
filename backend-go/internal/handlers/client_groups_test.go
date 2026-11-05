package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// A group is refused with a reason for every field the proxy would have to
// guess about, and saved normalised.
func TestClientGroupsAreValidatedAndNormalised(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	call(t, h, "POST", "/api/blacklists/import", `{"type":"domain","content":"games.example"}`)
	var sid int64
	_ = db.QueryRow("SELECT id FROM list_sources WHERE list = 'domain_blacklist'").Scan(&sid)
	s := strconv.FormatInt(sid, 10)

	for _, c := range []struct{ body, want string }{
		{`{"name":""}`, "the name is 1 to 40 letters"},
		{`{"name":"kids","members":["10.0.0.300"]}`, `"10.0.0.300" is not an IP address or network`},
		{`{"name":"kids","schedule":{"days":"MX","start":"07:00","end":"21:00"}}`, "days are letters among S M T W H F A"},
		{`{"name":"kids","schedule":{"days":"MTWHF","start":"21:00","end":"07:00"}}`, "the window ends after it starts, on the same day"},
		{`{"name":"kids","schedule":{"days":"MTWHF","start":"7:00","end":"21:00"}}`, "start and end are times of day, HH:MM"},
		{`{"name":"kids","lists":[` + s + `]}`, "applies to every client: set it to groups only first"},
		{`{"name":"kids","lists":[99999]}`, "source 99999 does not exist"},
		{`{"name":"kids","unknown":1}`, "invalid request body"},
	} {
		code, body := call(t, h, "POST", "/api/client-groups", c.body)
		if code != http.StatusBadRequest || !strings.Contains(body["detail"].(string), c.want) {
			t.Errorf("%s = %d %v, want 400 containing %q", c.body, code, body["detail"], c.want)
		}
	}

	if code, body := call(t, h, "PUT", "/api/domain-blacklist/sources/"+s+"/scope", `{"scope":"groups"}`); code != http.StatusOK {
		t.Fatalf("scope: %d %v", code, body)
	}
	code, body := call(t, h, "POST", "/api/client-groups",
		`{"name":"kids","members":["10.1.0.5","10.2.3.4/16","10.1.0.5"],"lists":[`+s+`],"schedule":{"days":"FMTWH","start":"07:00","end":"21:00"},"allowlist_only":true}`)
	if code != http.StatusOK {
		t.Fatalf("create: %d %v", code, body)
	}
	b, _ := json.Marshal(body["data"])
	var g database.ClientGroup
	_ = json.Unmarshal(b, &g)
	if strings.Join(g.Members, ",") != "10.1.0.5/32,10.2.0.0/16" || g.Schedule == nil || g.Schedule.Days != "MTWHF" || !g.AllowlistOnly || len(g.Lists) != 1 {
		t.Errorf("saved = %+v; want members 10.1.0.5/32,10.2.0.0/16, days MTWHF, allowlist only, one list", g)
	}
	if code, _ := call(t, h, "POST", "/api/client-groups", `{"name":"kids"}`); code != http.StatusConflict {
		t.Errorf("a second group named kids = %d, want 409", code)
	}
	if code, body := call(t, h, "PUT", "/api/domain-blacklist/sources/"+s+"/scope", `{"scope":"global"}`); code != http.StatusConflict {
		t.Errorf("making a source a group uses global = %d %v, want 409", code, body)
	}
	id := strconv.FormatInt(g.ID, 10)
	if code, _ := call(t, h, "DELETE", "/api/client-groups/"+id, ""); code != http.StatusOK {
		t.Errorf("delete = %d", code)
	}
	if code, _ := call(t, h, "GET", "/api/client-groups/"+id, ""); code != http.StatusNotFound {
		t.Errorf("deleted group still answers %d", code)
	}
	if code, _ := call(t, h, "PUT", "/api/domain-blacklist/sources/"+s+"/scope", `{"scope":"global"}`); code != http.StatusOK {
		t.Errorf("scope back to global once no group uses it = %d", code)
	}
}

// A source for groups only is out of the global lists and the DNS sinkhole,
// and in the group's file; an entry a global source also lists stays global;
// every file of the groups is in the manifest; a deleted group's files go.
func TestGroupListsAreExportedApartFromTheGlobalLists(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := listRouter(t, db, cfg)
	call(t, h, "POST", "/api/blacklists/import", `{"type":"domain","content":"games.example\nshared.example\nallowed.example"}`)
	call(t, h, "POST", "/api/blacklists/import", `{"type":"domain","content":"ads.example\nshared.example"}`)
	call(t, h, "POST", "/api/domain-whitelist", `{"domain":"allowed.example"}`)
	var groupsSrc int64
	_ = db.QueryRow("SELECT s.id FROM list_sources s JOIN domain_blacklist d ON d.source_id = s.id WHERE d.domain = 'games.example'").Scan(&groupsSrc)
	gs := strconv.FormatInt(groupsSrc, 10)
	call(t, h, "PUT", "/api/domain-blacklist/sources/"+gs+"/scope", `{"scope":"groups"}`)
	code, body := call(t, h, "POST", "/api/client-groups", `{"name":"kids","members":["10.1.0.0/24"],"lists":[`+gs+`],"schedule":{"days":"MTWHF","start":"07:00","end":"21:00"}}`)
	if code != http.StatusOK {
		t.Fatalf("create: %d %v", code, body)
	}
	gid := int64(body["data"].(map[string]any)["id"].(float64))

	if _, err := database.ExportBlacklistsCounted(db, cfg.ConfigDir); err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(cfg.ConfigDir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return string(b)
	}
	if got := read("domain_blacklist.txt"); got != "ads.example\nshared.example\n" {
		t.Errorf("global list = %q; want ads.example and shared.example (also listed globally), not games.example", got)
	}
	if hosts := read("dnsmasq.d/blocklist.hosts"); strings.Contains(hosts, "games.example") || !strings.Contains(hosts, "0.0.0.0 shared.example") {
		t.Errorf("DNS sinkhole = %q; want shared.example, not the groups-only games.example", hosts)
	}
	if got := read("groups/s" + gs + "_domain.txt"); got != "games.example\nshared.example\n" {
		t.Errorf("group list = %q; want its entries less allowed.example", got)
	}
	if got := read("groups/g" + strconv.FormatInt(gid, 10) + "_src.txt"); got != "10.1.0.0/24\n" {
		t.Errorf("members = %q", got)
	}
	wantLine := "group " + strconv.FormatInt(gid, 10) + " days=MTWHF start=07:00 end=21:00 allowlist_only=0 domain=" + gs + " ip=-\n"
	if got := read("groups/groups.conf"); got != wantLine {
		t.Errorf("groups.conf = %q, want %q", got, wantLine)
	}
	var m struct {
		Files map[string]struct{ SHA256 string } `json:"files"`
	}
	_ = json.Unmarshal([]byte(read("lists.manifest.json")), &m)
	for _, name := range []string{"groups/groups.conf", "groups/s" + gs + "_domain.txt", "groups/g" + strconv.FormatInt(gid, 10) + "_src.txt"} {
		sum := sha256.Sum256([]byte(read(name)))
		if m.Files[name].SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("manifest %s = %q, want the file's sha256", name, m.Files[name].SHA256)
		}
	}

	call(t, h, "DELETE", "/api/client-groups/"+strconv.FormatInt(gid, 10), "")
	if _, err := database.ExportBlacklistsCounted(db, cfg.ConfigDir); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(cfg.ConfigDir, "groups"))
	if len(entries) != 1 || entries[0].Name() != "groups.conf" || read("groups/groups.conf") != "" {
		t.Errorf("after the group went, groups/ holds %v; want only an empty groups.conf", entries)
	}
	// The source is still for groups only: no group uses it, and it stays out
	// of the global list.
	if got := read("domain_blacklist.txt"); strings.Contains(got, "games.example") {
		t.Errorf("a groups-only source no group uses reached the global list: %q", got)
	}
}
