package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

// The audit log records who changed what. A row is (username, action, target,
// details): action is a fixed key the Audit page turns into a sentence, target
// is what the change was about (an entry, a URL, country codes), and details
// carries the counts as a JSON object, so a page or a script can read a
// number without parsing prose.
//
// The list changes and their keys, with <list> one of ip_blacklist,
// domain_blacklist, ip_whitelist, domain_whitelist, egress_allowlist:
//
//	add_<list>            target entry, details the note typed with it
//	remove_<list>         target entry
//	bulk_remove_<list>    details {"removed"}
//	clear_<list>          details {"removed"}
//	import_<list>         target URL ("" for pasted text), details {"added","skipped","from","name"?,"bogon_skipped"?}
//	geo_block             target country codes, details {"added","countries","requested","failed"?}
//	remove_source_<list>  target the source's URL or country, details {"removed","kind","name"?}
//	restore_<list>        details {"added","skipped"}
//	refresh_blacklists    user "system", details per list {"added","fetched","failed","not_added"?}
//	rewrite_egress_wildcards  user "system", schema version 5, details {"rewritten","dropped","entries"}
//	retire_setting_value      user "system", schema version 8, target setting key, details {"value","truncated"?}
//	egress_provider_enabled        target provider name, details {"kind","shared_network"?,"url"?}
//	egress_provider_disabled       target provider name, details {"kind","url"?,"deleted"?}
//	egress_provider_refreshed      target provider name, details {"commit","v4_before","v4_after","v6_before","v6_after","ipv4_covered_before","ipv4_covered_after"}
//	egress_provider_refresh_failed target provider name, details {"kind","reason"}
//	egress_provider_held           target provider name, details {"commit","growth_pct","v4_before","v4_after","v6_before","v6_after","ipv4_covered_before","ipv4_covered_after"}
//	egress_provider_held_applied   target provider name, details {"commit","growth_pct","v4_before","v4_after","v6_before","v6_after","ipv4_covered_before","ipv4_covered_after"}
//
// Before these were recorded, clearing 640,929 domains and importing 71,140
// left no row at all: the log held only sign-ins and settings saves.

// auditListName is the name the audit log gives a list table. dst_allowlist is
// the egress allowlist; add_egress_allowlist was its key before the others.
func auditListName(table string) string {
	if table == "dst_allowlist" {
		return "egress_allowlist"
	}
	return table
}

// listColumns is the column that holds the entry of each list table.
var listColumns = map[string]string{
	"ip_blacklist":     "ip",
	"ip_whitelist":     "ip",
	"domain_blacklist": "domain",
	"domain_whitelist": "domain",
	"dst_allowlist":    "entry",
}

// requestUser is the signed-in user of an authenticated request, "" if none.
func requestUser(r *http.Request) string {
	user, _ := r.Context().Value(middleware.CtxUsername).(string)
	return user
}

// auditJSON writes details as a compact JSON object (keys sorted by
// encoding/json), or "" for none.
func auditJSON(details map[string]any) string {
	if len(details) == 0 {
		return ""
	}
	b, err := json.Marshal(details)
	if err != nil {
		return ""
	}
	return string(b)
}

// auditChange records one change made by the request's user.
func auditChange(db *sql.DB, r *http.Request, action, target string, details map[string]any) {
	database.Audit(db, requestUser(r), action, target, auditJSON(details))
}

// secretQueryKey matches the query parameters a list URL may carry a
// credential in (an Auth-Key, a token, a signature).
var secretQueryKey = regexp.MustCompile(`(?i)key|token|auth|secret|pass|sig|cred`)

// redactURL is a list URL as the audit log may keep it: no user or password,
// and the value of any query parameter named like a credential replaced. The
// log is exported to CSV and kept for a year; a feed's access key does not
// belong in it.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(a URL that could not be parsed)"
	}
	u.User = nil
	if u.RawQuery != "" {
		q := u.Query()
		for k := range q {
			if secretQueryKey.MatchString(k) {
				q.Set(k, "redacted")
			}
		}
		u.RawQuery = q.Encode()
	}
	return u.String()
}
