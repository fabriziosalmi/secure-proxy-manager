package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

// listRoute is one list the Blacklists page manages: its URL segment, its
// table and the column that holds the entry. The export query is a constant
// per list, so no SQL is built from the request.
type listRoute struct {
	path, table, col, exportQuery string
}

var listRoutes = []listRoute{
	{"ip-blacklist", "ip_blacklist", "ip", "SELECT ip FROM ip_blacklist ORDER BY id"},
	{"domain-blacklist", "domain_blacklist", "domain", "SELECT domain FROM domain_blacklist ORDER BY id"},
	{"ip-whitelist", "ip_whitelist", "ip", "SELECT ip FROM ip_whitelist ORDER BY id"},
	{"domain-whitelist", "domain_whitelist", "domain", "SELECT domain FROM domain_whitelist ORDER BY id"},
}

// registerListSources adds, for every list, where its entries came from
// (GET .../sources), the removal of one source's entries (DELETE
// .../sources/{id}, or .../sources/unrecorded for the entries whose source was
// not recorded), and a download of the whole list (GET .../export).
func (h *BlacklistHandlers) registerListSources(r chi.Router, authMW func(http.Handler) http.Handler) {
	for _, l := range listRoutes {
		r.With(authMW).Get("/api/"+l.path+"/sources", h.listSources(l))
		r.With(authMW).Delete("/api/"+l.path+"/sources/{id}", h.removeSource(l))
		r.With(authMW).Get("/api/"+l.path+"/export", h.exportList(l))
	}
	r.With(authMW).Get("/api/blacklists/enforcement", h.Enforcement)
}

func (h *BlacklistHandlers) listSources(l listRoute) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sources, err := database.ListSources(h.db, l.table)
		if err != nil {
			writeInternalError(w, "list_sources", err)
			return
		}
		writeList(w, sources, ListMeta{Total: len(sources), Limit: len(sources), Offset: 0})
	}
}

// removeSource deletes the entries one source added, then asks for an export,
// the same path every other list change takes, so the proxy and the DNS
// sinkhole stop enforcing them.
func (h *BlacklistHandlers) removeSource(l listRoute) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := chi.URLParam(r, "id")
		var id int64
		if raw != database.SourceUnrecorded {
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || n <= 0 {
				writeError(w, http.StatusBadRequest, "id must be a source id or 'unrecorded'")
				return
			}
			var known int
			if err := h.db.QueryRow("SELECT COUNT(*) FROM list_sources WHERE id = ? AND list = ?", n, l.table).Scan(&known); err != nil {
				writeInternalError(w, "remove_source", err)
				return
			}
			if known == 0 {
				writeError(w, http.StatusNotFound, "source not found on this list")
				return
			}
			id = n
		}
		removed, err := database.RemoveSource(h.db, l.table, id)
		if err != nil {
			writeInternalError(w, "remove_source", err)
			return
		}
		if removed > 0 {
			requestExport()
		}
		if user, ok := r.Context().Value(middleware.CtxUsername).(string); ok {
			database.Audit(h.db, user, "remove_source_"+l.table, "source="+raw, fmt.Sprintf("%d entries removed", removed))
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":  "success",
			"message": fmt.Sprintf("Removed %d entries", removed),
			"data":    map[string]any{"removed": removed},
		})
	}
}

// exportList writes every entry of a list, one per line, in the order they
// were added. The page's Export used to save the 50 entries on screen.
func (h *BlacklistHandlers) exportList(l listRoute) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := h.db.Query(l.exportQuery)
		if err != nil {
			writeInternalError(w, "export_list", err)
			return
		}
		defer rows.Close()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s-%s.txt", l.path, time.Now().UTC().Format("2006-01-02")))
		bw := bufio.NewWriter(w)
		for rows.Next() {
			var v string
			// A stored value that could split a line stays out of the
			// download, as the exporter keeps it out of the enforcement files.
			if rows.Scan(&v) == nil && database.LineSafe(v) {
				_, _ = bw.WriteString(v)
				_ = bw.WriteByte('\n')
			}
		}
		_ = bw.Flush()
	}
}

// IPACLStatus is what the proxy's watchdog recorded after merging an IP list
// for Squid (normalize_ip_file in proxy/blacklist_watchdog.py): the list had
// Entries lines, Squid loads Networks networks, and Dropped lines were not an
// address or CIDR.
type IPACLStatus struct {
	Entries   int   `json:"entries"`
	Networks  int   `json:"networks"`
	Dropped   int   `json:"dropped"`
	WrittenAt int64 `json:"written_at"`
}

// readIPACLStatus returns the proxy's record, or nil when there is none (a
// proxy older than the record, one that has not started, or one whose last
// merge failed) or it cannot be read.
func readIPACLStatus(configDir, name string) *IPACLStatus {
	raw, err := os.ReadFile(filepath.Join(configDir, name)) // #nosec G304 -- fixed names in the config dir
	if err != nil {
		return nil
	}
	var s struct {
		Version   int   `json:"version"`
		Entries   *int  `json:"entries"`
		Networks  *int  `json:"networks"`
		Dropped   *int  `json:"dropped"`
		WrittenAt int64 `json:"written_at"`
	}
	if json.Unmarshal(raw, &s) != nil || s.Version != 1 || s.Entries == nil || s.Networks == nil || s.Dropped == nil {
		return nil
	}
	return &IPACLStatus{Entries: *s.Entries, Networks: *s.Networks, Dropped: *s.Dropped, WrittenAt: s.WrittenAt}
}

// Enforcement says what really enforces each list, from recorded state only:
// the domain limit the backend applies, how many blocked domains the allowed
// list takes out of the exported files, and the proxy's own records of what
// Squid holds. A record the proxy has not written is null, never a guess.
func (h *BlacklistHandlers) Enforcement(w http.ResponseWriter, r *http.Request) {
	var domains, allowed int
	if err := h.db.QueryRow("SELECT COUNT(*) FROM domain_blacklist").Scan(&domains); err != nil {
		writeInternalError(w, "enforcement", err)
		return
	}
	// The exporter leaves out a blocked domain whose exact name is on the
	// allowed list (loadWhitelistSet), so neither dnsmasq nor Squid gets it.
	if err := h.db.QueryRow(
		"SELECT COUNT(*) FROM domain_blacklist WHERE domain IN (SELECT domain FROM domain_whitelist WHERE type = 'fqdn')",
	).Scan(&allowed); err != nil {
		writeInternalError(w, "enforcement", err)
		return
	}
	writeOK(w, map[string]any{
		"dns_blocklist_limit":         database.DomainBlacklistLimit(),
		"domain_blacklist_entries":    domains,
		"domain_blacklist_on_allowed": allowed,
		"squid_domain_acl":            nullable(readDomainACLStatus(h.cfg.ConfigDir)),
		"squid_ip_blacklist":          nullable(readIPACLStatus(h.cfg.ConfigDir, "ip_blacklist_acl_status.json")),
		"squid_ip_whitelist":          nullable(readIPACLStatus(h.cfg.ConfigDir, "ip_whitelist_acl_status.json")),
	})
}

// nullable turns a nil record pointer into a JSON null rather than a typed nil
// inside an interface, which encoding/json also writes as null; it exists to
// make that explicit at the call site.
func nullable[T any](p *T) any {
	if p == nil {
		return nil
	}
	return p
}
