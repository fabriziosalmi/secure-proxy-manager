package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

// A list the dashboard shows, under its name there (Blacklists page tabs and
// the Default-deny allowlist page).
type listDef struct {
	noun, label, path, field string
	importPath               string // "" when the list has no import
	importType               string // the type blacklists/import takes; "" for the list's own /import
	export                   bool
}

var lists = []listDef{
	{"blocked-ips", "Blocked IPs", "/api/ip-blacklist", "ip", "/api/blacklists/import", "ip", true},
	{"blocked-domains", "Blocked domains", "/api/domain-blacklist", "domain", "/api/blacklists/import", "domain", true},
	{"ip-exceptions", "IP exceptions", "/api/ip-whitelist", "ip", "/api/ip-whitelist/import", "", true},
	{"domain-exceptions", "Domain exceptions", "/api/domain-whitelist", "domain", "/api/domain-whitelist/import", "", true},
	{"allowlist", "Default-deny allowlist", "/api/egress-allowlist", "entry", "", "", false},
}

// commandOperations is every API operation a curated command calls, as
// "METHOD /path" of the OpenAPI document. The registry marks exactly these
// cli (backend-go/internal/handlers/surfaces.go), and a test holds the two to
// each other.
func commandOperations() []string {
	set := map[string]bool{"GET /api/status": true}
	for _, l := range lists {
		set["GET "+l.path] = true
		set["POST "+l.path] = true
		set["DELETE "+l.path+"/{id}"] = true
		set["DELETE "+l.path+"/clear-all"] = true
		if l.importPath != "" {
			set["POST "+l.importPath] = true
		}
		if l.export {
			set["GET "+l.path+"/export"] = true
			set["GET "+l.path+"/sources"] = true
		}
	}
	for _, k := range []string{
		"GET /api/config/snapshots", "POST /api/config/snapshots",
		"GET /api/config/snapshots/{id}/diff", "POST /api/config/snapshots/{id}/restore",
		"GET /api/security/rate-limits", "DELETE /api/security/rate-limits/{ip}",
		"GET /api/settings", "PUT /api/settings/{name}",
		"GET /api/logs",
	} {
		set[k] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// CommandOperations is commandOperations for the registry test.
func CommandOperations() []string { return commandOperations() }

const nounUsage = `
  spm blocked-ips | blocked-domains | ip-exceptions | domain-exceptions
      list [--search TEXT] [--limit N] | add VALUE [--note TEXT] |
      remove VALUE | clear --yes | import FILE | export | sources
  spm allowlist list | add VALUE [--subdomains] [--note TEXT] | remove VALUE | clear --yes
  spm history list | take [--note TEXT] | diff ID | restore ID --yes
  spm sign-in-limits list | clear IP
  spm settings get [NAME] | set NAME VALUE
  spm logs [--blocked] [--search TEXT] [--limit N]
`

// session is a command's resolved settings and client.
type session struct {
	c      common
	cl     *client
	stdout io.Writer
	stderr io.Writer
}

func newSession(name string, args []string, stdout, stderr io.Writer, extra func(*flag.FlagSet)) (*session, []string, int) {
	var c common
	fs := newFlags(name, stderr, &c)
	if extra != nil {
		extra(fs)
	}
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return nil, nil, exitUsage
	}
	_, cfg, ok := c.config(stderr)
	if !ok {
		return nil, nil, exitUsage
	}
	cl, err := newClient(cfg, c.insecure)
	if err != nil {
		fmt.Fprintf(stderr, "spm: %v\n", err)
		return nil, nil, exitUsage
	}
	return &session{c: c, cl: cl, stdout: stdout, stderr: stderr}, pos, exitOK
}

// call sends one request and, on a 2xx, returns the answer's data; otherwise
// it prints why and gives the exit status.
func (s *session) call(method, path string, body any) (json.RawMessage, *response, int) {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	r, err := s.cl.do(method, path, b)
	if err != nil {
		return nil, nil, failure(s.stderr, err)
	}
	warnVersion(s.stderr, r)
	if code := exitFor(r.status); code != exitOK {
		var e struct {
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(r.body, &e)
		if e.Detail == "" {
			e.Detail = strings.TrimSpace(string(r.body))
		}
		fmt.Fprintf(s.stderr, "spm: %s %s answered %d: %s\n", method, path, r.status, e.Detail)
		return nil, r, code
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(r.body, &env) != nil || len(env.Data) == 0 {
		return r.body, r, exitOK
	}
	return env.Data, r, exitOK
}

// print writes data as JSON with --json, otherwise with table.
func (s *session) print(data json.RawMessage, table func(json.RawMessage)) {
	if s.c.json || table == nil {
		var pretty bytes.Buffer
		if json.Indent(&pretty, data, "", "  ") == nil {
			fmt.Fprintf(s.stdout, "%s\n", pretty.Bytes())
			return
		}
		fmt.Fprintf(s.stdout, "%s\n", data)
		return
	}
	table(data)
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

// rows prints the given fields of each object, one row each, under a header.
func (s *session) rows(data json.RawMessage, header []string, fields []string) {
	var items []map[string]any
	if json.Unmarshal(data, &items) != nil {
		fmt.Fprintf(s.stdout, "%s\n", data)
		return
	}
	widths := make([]int, len(header))
	cells := make([][]string, 0, len(items))
	for i, h := range header {
		widths[i] = len(h)
	}
	for _, it := range items {
		row := make([]string, len(fields))
		for i, f := range fields {
			row[i] = str(it[f])
			if len(row[i]) > widths[i] {
				widths[i] = len(row[i])
			}
		}
		cells = append(cells, row)
	}
	line := func(cols []string) {
		var b strings.Builder
		for i, c := range cols {
			if i == len(cols)-1 {
				b.WriteString(c)
			} else {
				fmt.Fprintf(&b, "%-*s  ", widths[i], c)
			}
		}
		fmt.Fprintf(s.stdout, "%s\n", strings.TrimRight(b.String(), " "))
	}
	line(header)
	for _, r := range cells {
		line(r)
	}
	if len(items) == 0 {
		fmt.Fprintf(s.stdout, "(none)\n")
	}
}

func listByNoun(noun string) (listDef, bool) {
	for _, l := range lists {
		if l.noun == noun {
			return l, true
		}
	}
	return listDef{}, false
}

// findEntry is the id of the entry whose value is exactly v.
func (s *session) findEntry(l listDef, v string) (string, int) {
	data, _, code := s.call("GET", l.path+"?limit=1000&search="+url.QueryEscape(v), nil)
	if code != exitOK {
		return "", code
	}
	var items []map[string]any
	_ = json.Unmarshal(data, &items)
	want := strings.TrimPrefix(strings.ToLower(v), "*.")
	for _, it := range items {
		have := strings.TrimPrefix(strings.ToLower(str(it[l.field])), ".")
		if have == want || strings.EqualFold(str(it[l.field]), v) {
			return str(it["id"]), exitOK
		}
	}
	fmt.Fprintf(s.stderr, "spm: %s is not on %s\n", v, l.label)
	return "", exitRefused
}

func runList(l listDef, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "spm %s: give list, add, remove, clear%s\n", l.noun, map[bool]string{true: ", import, export or sources", false: ""}[l.export])
		return exitUsage
	}
	verb, rest := args[0], args[1:]
	var search, note string
	var limit int
	var yes, subdomains bool
	s, pos, code := newSession(l.noun+" "+verb, rest, stdout, stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&search, "search", "", "only entries containing this text")
		fs.IntVar(&limit, "limit", 100, "at most this many entries (1 to 1000)")
		fs.StringVar(&note, "note", "", "a note kept with the entry")
		fs.BoolVar(&yes, "yes", false, "confirm clearing the whole list")
		if l.noun == "allowlist" {
			fs.BoolVar(&subdomains, "subdomains", false, "a domain and every name under it")
		}
	})
	if code != exitOK {
		return code
	}
	need := func(n int, what string) bool {
		if len(pos) != n {
			fmt.Fprintf(stderr, "spm %s %s: give %s\n", l.noun, verb, what)
			return false
		}
		return true
	}
	switch verb {
	case "list":
		if !need(0, "no argument") {
			return exitUsage
		}
		q := fmt.Sprintf("?limit=%d", limit)
		if search != "" {
			q += "&search=" + url.QueryEscape(search)
		}
		data, _, code := s.call("GET", l.path+q, nil)
		if code == exitOK {
			s.print(data, func(d json.RawMessage) {
				s.rows(d, []string{"ID", strings.ToUpper(l.field), "ADDED", "NOTE"}, []string{"id", l.field, "added_date", "description"})
			})
		}
		return code
	case "add":
		if !need(1, "the entry, e.g. 203.0.113.7 or ads.example.com") {
			return exitUsage
		}
		body := map[string]any{l.field: pos[0], "description": note}
		if subdomains {
			body["include_subdomains"] = true
		}
		_, r, code := s.call("POST", l.path, body)
		if code == exitOK {
			fmt.Fprintf(stdout, "%s\n", messageOf(r, "Added "+pos[0]+" to "+l.label))
		}
		return code
	case "remove":
		if !need(1, "the entry to remove") {
			return exitUsage
		}
		id, code := s.findEntry(l, pos[0])
		if code != exitOK {
			return code
		}
		if _, _, code = s.call("DELETE", l.path+"/"+id, nil); code == exitOK {
			fmt.Fprintf(stdout, "Removed %s from %s\n", pos[0], l.label)
		}
		return code
	case "clear":
		if !need(0, "no argument") {
			return exitUsage
		}
		if !yes {
			fmt.Fprintf(stderr, "spm %s clear: this removes every entry of %s; add --yes to do it\n", l.noun, l.label)
			return exitUsage
		}
		data, _, code := s.call("DELETE", l.path+"/clear-all", nil)
		if code == exitOK {
			var d struct {
				Removed int `json:"removed"`
			}
			_ = json.Unmarshal(data, &d)
			fmt.Fprintf(stdout, "Removed %d entries from %s\n", d.Removed, l.label)
		}
		return code
	case "import":
		if l.importPath == "" {
			fmt.Fprintf(stderr, "spm %s: %s has no import\n", l.noun, l.label)
			return exitUsage
		}
		if !need(1, "a file with one entry per line, or - for standard input") {
			return exitUsage
		}
		var content []byte
		var err error
		if pos[0] == "-" {
			content, err = io.ReadAll(stdin)
		} else {
			content, err = os.ReadFile(pos[0]) // #nosec G304 -- a file the person named
		}
		if err != nil {
			fmt.Fprintf(stderr, "spm %s import: %v\n", l.noun, err)
			return exitUsage
		}
		body := map[string]any{"content": string(content)}
		if l.importType != "" {
			body["type"] = l.importType
		}
		data, _, code := s.call("POST", l.importPath, body)
		if code == exitOK {
			s.print(data, nil)
		}
		return code
	case "export":
		if !l.export {
			fmt.Fprintf(stderr, "spm %s: %s has no export\n", l.noun, l.label)
			return exitUsage
		}
		r, err := s.cl.do("GET", l.path+"/export", nil)
		if err != nil {
			return failure(stderr, err)
		}
		if exitFor(r.status) != exitOK {
			fmt.Fprintf(stderr, "spm: export answered %d\n", r.status)
			return exitFor(r.status)
		}
		_, _ = stdout.Write(r.body)
		return exitOK
	case "sources":
		if !l.export {
			fmt.Fprintf(stderr, "spm %s: %s has no sources\n", l.noun, l.label)
			return exitUsage
		}
		data, _, code := s.call("GET", l.path+"/sources", nil)
		if code == exitOK {
			s.print(data, func(d json.RawMessage) {
				s.rows(d, []string{"ID", "KIND", "ENTRIES", "SOURCE", "LABEL"}, []string{"id", "kind", "entries", "source", "label"})
			})
		}
		return code
	}
	fmt.Fprintf(stderr, "spm %s: no verb %q\n", l.noun, verb)
	return exitUsage
}

func messageOf(r *response, fallback string) string {
	var m struct {
		Message string `json:"message"`
	}
	if r != nil && json.Unmarshal(r.body, &m) == nil && m.Message != "" {
		return m.Message
	}
	return fallback
}

func runHistory(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "spm history: give list, take, diff or restore\n")
		return exitUsage
	}
	verb := args[0]
	var note string
	var yes bool
	s, pos, code := newSession("history "+verb, args[1:], stdout, stderr, func(fs *flag.FlagSet) {
		fs.StringVar(&note, "note", "", "a note for the snapshot")
		fs.BoolVar(&yes, "yes", false, "confirm the restore")
	})
	if code != exitOK {
		return code
	}
	idArg := func() (string, bool) {
		if len(pos) != 1 {
			fmt.Fprintf(stderr, "spm history %s: give the snapshot ID (spm history list)\n", verb)
			return "", false
		}
		if _, err := strconv.Atoi(pos[0]); err != nil {
			fmt.Fprintf(stderr, "spm history %s: %q is not a snapshot ID\n", verb, pos[0])
			return "", false
		}
		return pos[0], true
	}
	switch verb {
	case "list":
		data, _, code := s.call("GET", "/api/config/snapshots", nil)
		if code == exitOK {
			s.print(data, func(d json.RawMessage) {
				s.rows(d, []string{"ID", "TAKEN", "BY", "IN FORCE", "REASON"}, []string{"id", "created_at", "username", "current", "reason"})
			})
		}
		return code
	case "take":
		body := map[string]any{}
		if note != "" {
			body["note"] = note
		}
		data, _, code := s.call("POST", "/api/config/snapshots", body)
		if code == exitOK {
			s.print(data, nil)
		}
		return code
	case "diff":
		id, ok := idArg()
		if !ok {
			return exitUsage
		}
		data, _, code := s.call("GET", "/api/config/snapshots/"+id+"/diff", nil)
		if code == exitOK {
			s.print(data, nil)
		}
		return code
	case "restore":
		id, ok := idArg()
		if !ok {
			return exitUsage
		}
		if !yes {
			fmt.Fprintf(stderr, "spm history restore: this makes the configuration snapshot %s's (spm history diff %s shows what changes); add --yes to do it\n", id, id)
			return exitUsage
		}
		data, _, code := s.call("POST", "/api/config/snapshots/"+id+"/restore", map[string]any{})
		if code == exitOK {
			s.print(data, nil)
		}
		return code
	}
	fmt.Fprintf(stderr, "spm history: no verb %q\n", verb)
	return exitUsage
}

func runSignInLimits(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "spm sign-in-limits: give list or clear IP\n")
		return exitUsage
	}
	verb := args[0]
	s, pos, code := newSession("sign-in-limits "+verb, args[1:], stdout, stderr, nil)
	if code != exitOK {
		return code
	}
	switch verb {
	case "list":
		data, _, code := s.call("GET", "/api/security/rate-limits", nil)
		if code == exitOK {
			s.print(data, func(d json.RawMessage) {
				s.rows(d, []string{"ADDRESS", "FAILED", "REFUSED", "UNTIL"}, []string{"ip", "attempts", "blocked", "until"})
			})
		}
		return code
	case "clear":
		if len(pos) != 1 {
			fmt.Fprintf(stderr, "spm sign-in-limits clear: give the address\n")
			return exitUsage
		}
		if _, _, code = s.call("DELETE", "/api/security/rate-limits/"+url.PathEscape(pos[0]), nil); code == exitOK {
			fmt.Fprintf(stdout, "%s can sign in again\n", pos[0])
		}
		return code
	}
	fmt.Fprintf(stderr, "spm sign-in-limits: no verb %q\n", verb)
	return exitUsage
}

func runSettings(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintf(stderr, "spm settings: give get [NAME] or set NAME VALUE\n")
		return exitUsage
	}
	verb := args[0]
	s, pos, code := newSession("settings "+verb, args[1:], stdout, stderr, nil)
	if code != exitOK {
		return code
	}
	switch verb {
	case "get":
		if len(pos) > 1 {
			fmt.Fprintf(stderr, "spm settings get: give at most one name\n")
			return exitUsage
		}
		data, _, code := s.call("GET", "/api/settings", nil)
		if code != exitOK {
			return code
		}
		if len(pos) == 1 {
			var items []map[string]any
			_ = json.Unmarshal(data, &items)
			for _, it := range items {
				if str(it["setting_name"]) == pos[0] {
					b, _ := json.Marshal([]map[string]any{it})
					data = b
					s.print(data, func(d json.RawMessage) {
						s.rows(d, []string{"NAME", "VALUE"}, []string{"setting_name", "setting_value"})
					})
					return exitOK
				}
			}
			fmt.Fprintf(stderr, "spm settings get: no setting %q\n", pos[0])
			return exitRefused
		}
		s.print(data, func(d json.RawMessage) {
			s.rows(d, []string{"NAME", "VALUE"}, []string{"setting_name", "setting_value"})
		})
		return exitOK
	case "set":
		if len(pos) != 2 {
			fmt.Fprintf(stderr, "spm settings set: give NAME VALUE\n")
			return exitUsage
		}
		if _, r, code := s.call("PUT", "/api/settings/"+url.PathEscape(pos[0]), map[string]any{"value": pos[1]}); code == exitOK {
			fmt.Fprintf(stdout, "%s\n", messageOf(r, "Saved "+pos[0]))
		} else {
			return code
		}
		return exitOK
	}
	fmt.Fprintf(stderr, "spm settings: no verb %q\n", verb)
	return exitUsage
}

func runLogs(args []string, stdout, stderr io.Writer) int {
	var blocked bool
	var search string
	var limit int
	s, pos, code := newSession("logs", args, stdout, stderr, func(fs *flag.FlagSet) {
		fs.BoolVar(&blocked, "blocked", false, "only the blocked requests")
		fs.StringVar(&search, "search", "", "only requests whose host or URL contains this text")
		fs.IntVar(&limit, "limit", 25, "at most this many requests")
	})
	if code != exitOK {
		return code
	}
	if len(pos) != 0 {
		fmt.Fprintf(stderr, "spm logs: takes no argument; see --blocked, --search, --limit\n")
		return exitUsage
	}
	q := fmt.Sprintf("?limit=%d", limit)
	if blocked {
		q += "&outcome=blocked"
	}
	if search != "" {
		q += "&q=" + url.QueryEscape(search)
	}
	data, _, code := s.call("GET", "/api/logs"+q, nil)
	if code == exitOK {
		s.print(data, func(d json.RawMessage) {
			s.rows(d, []string{"TIME", "CLIENT", "METHOD", "DESTINATION", "STATUS", "RULE"}, []string{"timestamp", "source_ip", "method", "destination", "status", "reason"})
		})
	}
	return code
}
