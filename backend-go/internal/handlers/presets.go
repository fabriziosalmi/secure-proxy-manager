package handlers

import (
	"database/sql"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// A preset is a named group of domains added to one list in one request: the
// common services a network usually needs on Allowed domains, and the public
// DNS-over-HTTPS resolvers on Blocked domains (so a device cannot step around
// the DNS sinkhole). The groups used to live in the UI, which added each
// domain with its own request: every domain became a "Manual" entry, one audit
// row each, and the page could not say which group was already added.
//
// Now the backend holds the groups. Adding one records its domains under a
// source of their own (kind preset, keyed by the preset id), writes one audit
// event, and requests one export, which also reloads the DNS sinkhole. A
// domain already on the list keeps the source that added it first, as with
// every other source (database/sources.go).
type listPreset struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

// presetTables is the SQL name of each list that has presets.
var presetTables = map[string]database.SQLText{
	"domain_whitelist": "domain_whitelist",
	"domain_blacklist": "domain_blacklist",
}

// presetSourcePrefix is the label of a preset's source: "Common services: Docker".
const presetSourcePrefix = "Common services: "

var presetLists = map[string][]listPreset{
	"domain_whitelist": {
		{ID: "github", Name: "GitHub", Domains: []string{"github.com", "raw.githubusercontent.com", "api.github.com", "gist.github.com", "objects.githubusercontent.com"}},
		{ID: "google", Name: "Google", Domains: []string{"google.com", "www.google.com", "accounts.google.com", "apis.google.com", "fonts.googleapis.com", "fonts.gstatic.com"}},
		{ID: "microsoft", Name: "Microsoft", Domains: []string{"microsoft.com", "login.microsoftonline.com", "graph.microsoft.com", "outlook.office.com"}},
		{ID: "ai-services", Name: "AI Services", Domains: []string{"openai.com", "api.openai.com", "claude.ai", "api.anthropic.com", "gemini.google.com", "bard.google.com"}},
		{ID: "docker", Name: "Docker", Domains: []string{"docker.com", "hub.docker.com", "registry.docker.io", "auth.docker.io", "production.cloudflare.docker.com"}},
		{ID: "cdn-js", Name: "CDN/JS", Domains: []string{"cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "npmjs.org", "registry.npmjs.org"}},
		// Not 1.1.1.1 (an address, which Allowed domains refuses) nor
		// one.one.one.one (a DoH resolver, which the doh preset blocks).
		{ID: "cloudflare", Name: "Cloudflare", Domains: []string{"cloudflare.com", "dash.cloudflare.com"}},
	},
	"domain_blacklist": {
		{ID: "doh", Name: "DNS-over-HTTPS resolvers", Domains: []string{
			"dns.google", "dns.google.com", "dns64.dns.google",
			"cloudflare-dns.com", "mozilla.cloudflare-dns.com", "one.one.one.one",
			"doh.opendns.com", "dns.quad9.net", "doh.cleanbrowsing.org",
			"dns.adguard.com", "doh.appliedprivacy.net", "doh.li",
			"dns.nextdns.io", "dns.controld.com",
		}},
	},
}

// presetState is a preset as GET {list}/presets returns it: which of its
// domains the list already holds, whatever source added them.
type presetState struct {
	listPreset
	Listed []string `json:"listed"`
}

func findPreset(table, id string) (listPreset, bool) {
	for _, p := range presetLists[table] {
		if p.ID == id {
			return p, true
		}
	}
	return listPreset{}, false
}

// listedDomains returns the domains of names that table holds, as stored.
func listedDomains(db *sql.DB, table string, names []string) ([]string, error) {
	// #nosec G202 -- the table is a constant of presetTables; values are bound.
	q := "SELECT domain FROM " + presetTables[table] + " WHERE domain IN (" + placeholders(len(names)) + ")"
	rows, err := db.Query(string(q), toArgs(names)...) // slopless-disable-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		have[d] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := []string{}
	for _, n := range names {
		if have[n] {
			out = append(out, n)
		}
	}
	return out, nil
}

func (h *BlacklistHandlers) registerPresets(r chi.Router, authMW func(http.Handler) http.Handler) {
	for _, l := range []struct{ path, table string }{
		{"domain-whitelist", "domain_whitelist"},
		{"domain-blacklist", "domain_blacklist"},
	} {
		r.With(authMW).Get("/api/"+l.path+"/presets", h.listPresets(l.table))
		r.With(authMW).Post("/api/"+l.path+"/presets/{preset}", h.addPreset(l.table))
	}
}

// listPresets answers the presets of a list, each with the domains already on
// it, so the page can say "5 of 5 added" before anything is clicked.
func (h *BlacklistHandlers) listPresets(table string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out := make([]presetState, 0, len(presetLists[table]))
		for _, p := range presetLists[table] {
			listed, err := listedDomains(h.db, table, p.Domains)
			if err != nil {
				writeInternalError(w, "list_presets", err)
				return
			}
			out = append(out, presetState{listPreset: p, Listed: listed})
		}
		writeOK(w, out)
	}
}

// addPreset adds every domain of a preset the list does not hold yet, under
// the preset's source, in one transaction. The answer and the one audit event
// say which were added and which were already listed.
func (h *BlacklistHandlers) addPreset(table string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := findPreset(table, chi.URLParam(r, "preset"))
		if !ok {
			writeError(w, http.StatusNotFound, "no such preset")
			return
		}
		for _, d := range p.Domains {
			if table == "domain_whitelist" {
				if _, refusal := allowedDomainValue(d); refusal != "" {
					writeInternalError(w, "add_preset", errPresetDomain(d, refusal))
					return
				}
			} else if !isValidHostname(d) {
				writeInternalError(w, "add_preset", errPresetDomain(d, notADomainMessage(d)))
				return
			}
		}
		listed, err := listedDomains(h.db, table, p.Domains)
		if err != nil {
			writeInternalError(w, "add_preset", err)
			return
		}
		already := map[string]bool{}
		for _, d := range listed {
			already[d] = true
		}
		var missing []string
		for _, d := range p.Domains {
			if !already[d] {
				missing = append(missing, d)
			}
		}
		if table == "domain_blacklist" && len(missing) > 0 {
			if limit := database.DomainBlacklistLimit(); h.domainCount()+len(missing) > limit {
				writeError(w, http.StatusRequestEntityTooLarge, domainLimitMessage(limit))
				return
			}
		}

		added := []string{}
		if len(missing) > 0 {
			tx, err := h.db.Begin()
			if err != nil {
				writeInternalError(w, "add_preset", err)
				return
			}
			defer tx.Rollback() //nolint:errcheck // no-op once committed
			sourceID, err := database.KeyedSource(tx, table, database.SourcePreset, p.ID, presetSourcePrefix+p.Name)
			if err != nil {
				writeInternalError(w, "add_preset", err)
				return
			}
			// #nosec G202 -- the table is a constant of presetTables; values are bound.
			insert := "INSERT OR IGNORE INTO " + presetTables[table] + "(domain, description, source_id) VALUES(?, '', ?)"
			for _, d := range missing {
				res, err := tx.Exec(string(insert), d, sourceID) // slopless-disable-line VBC-004 -- SQL text is SQLText from constants and placeholders, values are bound (database/sqltext.go)
				if err != nil {
					writeInternalError(w, "add_preset", err)
					return
				}
				if n, _ := res.RowsAffected(); n == 1 {
					added = append(added, d)
				}
			}
			if err := tx.Commit(); err != nil {
				writeInternalError(w, "add_preset", err)
				return
			}
			requestExport()
		}
		alreadyListed := len(p.Domains) - len(added)
		auditChange(h.db, r, "add_preset_"+table, p.Name, map[string]any{
			"preset": p.ID, "added": len(added), "already": alreadyListed, "domains": added,
		})
		writeOK(w, map[string]any{
			"preset": p.ID, "name": p.Name, "added": added, "already": alreadyListed,
		})
	}
}

type presetDomainError struct{ domain, why string }

func (e presetDomainError) Error() string {
	return "preset domain " + e.domain + " is refused by its own list: " + strings.TrimSpace(e.why)
}

func errPresetDomain(d, why string) error { return presetDomainError{domain: d, why: why} }
