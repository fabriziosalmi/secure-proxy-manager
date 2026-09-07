package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/netguard"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

type BlacklistHandlers struct {
	db  *sql.DB
	cfg *config.Config
}

func NewBlacklistHandlers(db *sql.DB, cfg *config.Config) *BlacklistHandlers {
	return &BlacklistHandlers{db: db, cfg: cfg}
}

func (h *BlacklistHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	// IP blacklist
	r.With(authMW).Get("/api/ip-blacklist", listHandler(h.db, "ip_blacklist", "ip"))
	r.With(authMW).Post("/api/ip-blacklist", h.AddIP)
	r.With(authMW).Delete("/api/ip-blacklist/clear-all", clearAllHandler(h.db, "ip_blacklist", h.cfg, "ip"))
	r.With(authMW).Post("/api/ip-blacklist/bulk-delete", bulkDeleteHandler(h.db, "ip_blacklist", h.cfg))
	r.With(authMW).Delete("/api/ip-blacklist/{id}", deleteByIDHandler(h.db, "ip_blacklist", h.cfg))

	// IP whitelist
	r.With(authMW).Get("/api/ip-whitelist", listHandler(h.db, "ip_whitelist", "ip"))
	r.With(authMW).Post("/api/ip-whitelist", h.AddIPWhitelist)
	r.With(authMW).Delete("/api/ip-whitelist/{id}", deleteByIDHandler(h.db, "ip_whitelist", nil))

	// Domain blacklist
	r.With(authMW).Get("/api/domain-blacklist", listHandler(h.db, "domain_blacklist", "domain"))
	r.With(authMW).Post("/api/domain-blacklist", h.AddDomain)
	r.With(authMW).Delete("/api/domain-blacklist/clear-all", clearAllHandler(h.db, "domain_blacklist", h.cfg, "domain"))
	r.With(authMW).Post("/api/domain-blacklist/bulk-delete", bulkDeleteHandler(h.db, "domain_blacklist", h.cfg))
	r.With(authMW).Delete("/api/domain-blacklist/{id}", deleteByIDHandler(h.db, "domain_blacklist", h.cfg))

	// Domain whitelist
	r.With(authMW).Get("/api/domain-whitelist", listHandler(h.db, "domain_whitelist", "domain"))
	r.With(authMW).Post("/api/domain-whitelist", h.AddDomainWhitelist)
	r.With(authMW).Delete("/api/domain-whitelist/{id}", deleteByIDHandler(h.db, "domain_whitelist", nil))

	// Egress destination allowlist (default-deny egress). Single table, entries
	// classified as 'cidr' or 'domain'; pass h.cfg so deletes re-export.
	r.With(authMW).Get("/api/egress-allowlist", listHandler(h.db, "dst_allowlist", "entry"))
	r.With(authMW).Post("/api/egress-allowlist", h.AddDstAllow)
	r.With(authMW).Delete("/api/egress-allowlist/clear-all", clearAllHandler(h.db, "dst_allowlist", h.cfg, "entry"))
	r.With(authMW).Post("/api/egress-allowlist/bulk-delete", bulkDeleteHandler(h.db, "dst_allowlist", h.cfg))
	r.With(authMW).Delete("/api/egress-allowlist/{id}", deleteByIDHandler(h.db, "dst_allowlist", h.cfg))

	// Import endpoints
	r.With(authMW).Post("/api/blacklists/import", h.Import)
	r.With(authMW).Post("/api/blacklists/import-geo", h.ImportGeo)
	r.With(authMW).Post("/api/ip-blacklist/import", h.ImportIPLegacy)
	r.With(authMW).Post("/api/domain-blacklist/import", h.ImportDomainLegacy)
}

// ── generic list handler ──────────────────────────────────────────────────────

func listHandler(db *sql.DB, table, col string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := clamp(queryInt(r, "limit", 100), 1, 1000)
		offset := max0(queryInt(r, "offset", 0))
		search := r.URL.Query().Get("search")

		var total int
		var rows *sql.Rows
		var err error

		if search != "" {
			// Escape LIKE metacharacters
			escaped := strings.NewReplacer("%", "\\%", "_", "\\_").Replace(search)
			like := "%" + escaped + "%"
			db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\'", table, col), like, like).Scan(&total) //nolint:errcheck
			rows, err = db.Query(fmt.Sprintf("SELECT * FROM %s WHERE %s LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT ? OFFSET ?", table, col), like, like, limit, offset)
		} else {
			db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&total) //nolint:errcheck
			rows, err = db.Query(fmt.Sprintf("SELECT * FROM %s ORDER BY id DESC LIMIT ? OFFSET ?", table), limit, offset)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer rows.Close()
		cols, _ := rows.Columns()
		var result []map[string]any
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			rows.Scan(ptrs...) //nolint:errcheck
			row := map[string]any{}
			for i, c := range cols {
				row[c] = vals[i]
			}
			result = append(result, row)
		}
		if result == nil {
			result = []map[string]any{}
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "success", "data": result, "total": total, "limit": limit, "offset": offset,
		})
	}
}

func deleteByIDHandler(db *sql.DB, table string, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		res, err := db.Exec(fmt.Sprintf("DELETE FROM %s WHERE id=?", table), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			writeError(w, http.StatusNotFound, "entry not found")
			return
		}
		if cfg != nil {
			requestExport()
		}
		// Audit log
		if user, ok := r.Context().Value(middleware.CtxUsername).(string); ok {
			database.Audit(db, user, "delete_"+kindFromTable(table), "id="+id, table)
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "entry removed"})
	}
}

func bulkDeleteHandler(db *sql.DB, table string, cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req models.BulkDeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 {
			writeError(w, http.StatusBadRequest, "ids required")
			return
		}
		placeholders := strings.Repeat("?,", len(req.IDs))
		placeholders = placeholders[:len(placeholders)-1]
		args := make([]any, len(req.IDs))
		for i, id := range req.IDs {
			args[i] = id
		}
		res, err := db.Exec(fmt.Sprintf("DELETE FROM %s WHERE id IN (%s)", table, placeholders), args...)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "database error")
			return
		}
		deleted, _ := res.RowsAffected()
		if deleted > 0 && cfg != nil {
			requestExport()
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "success", "data": map[string]any{"deleted": deleted}})
	}
}

func clearAllHandler(db *sql.DB, table string, cfg *config.Config, col string) http.HandlerFunc {
	_ = col
	return func(w http.ResponseWriter, r *http.Request) {
		var count int
		db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count) //nolint:errcheck
		if _, err := db.Exec(fmt.Sprintf("DELETE FROM %s", table)); err != nil {
			writeError(w, http.StatusInternalServerError, "database error: "+err.Error())
			return
		}
		if cfg != nil {
			requestExport()
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "success", "message": fmt.Sprintf("Cleared %d entries", count)})
	}
}

// ── IP blacklist ──────────────────────────────────────────────────────────────

func (h *BlacklistHandlers) AddIP(w http.ResponseWriter, r *http.Request) {
	var item models.IPListItem
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ip := strings.TrimSpace(item.IP)
	if !isValidCIDR(ip) {
		writeError(w, http.StatusBadRequest, "invalid IP address or CIDR format")
		return
	}
	if isLANBogonCIDR(ip) {
		writeError(w, http.StatusBadRequest, "private/RFC1918/bogon ranges cannot be blacklisted — the IP blacklist is a source ACL, so this would block your own LAN clients")
		return
	}
	_, err := h.db.Exec("INSERT INTO ip_blacklist(ip, description) VALUES(?,?)", ip, item.Description)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusBadRequest, "IP address already in blacklist")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	requestExport()
	if user, ok := r.Context().Value(middleware.CtxUsername).(string); ok {
		database.Audit(h.db, user, "add_ip_blacklist", ip, item.Description)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "IP added to blacklist"})
}

func (h *BlacklistHandlers) AddIPWhitelist(w http.ResponseWriter, r *http.Request) {
	var item models.IPListItem
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ip := strings.TrimSpace(item.IP)
	if !isValidCIDR(ip) {
		writeError(w, http.StatusBadRequest, "invalid IP/Network format")
		return
	}
	_, err := h.db.Exec("INSERT INTO ip_whitelist(ip, description) VALUES(?,?)", ip, item.Description)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusBadRequest, "IP already in whitelist")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "IP added to whitelist"})
}

// ── Domain blacklist ──────────────────────────────────────────────────────────

func (h *BlacklistHandlers) AddDomain(w http.ResponseWriter, r *http.Request) {
	var item models.DomainListItem
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	domain := strings.TrimSpace(strings.ToLower(item.Domain))
	if domain == "" || strings.ContainsAny(domain, " ") || strings.HasPrefix(domain, "-") {
		writeError(w, http.StatusBadRequest, "invalid domain format")
		return
	}
	// Strip URL scheme if present.
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		u, err := url.Parse(domain)
		if err != nil || u.Host == "" {
			writeError(w, http.StatusBadRequest, "invalid domain URL")
			return
		}
		domain = u.Host
	}
	_, err := h.db.Exec("INSERT INTO domain_blacklist(domain, description) VALUES(?,?)", domain, item.Description)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusBadRequest, "domain already in blacklist")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	requestExport()
	if user, ok := r.Context().Value(middleware.CtxUsername).(string); ok {
		database.Audit(h.db, user, "add_domain_blacklist", domain, item.Description)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Domain added to blacklist"})
}

// AddDstAllow adds an entry to the egress destination allowlist (default-deny
// egress). The entry is auto-classified: an IP or CIDR is stored as 'cidr'
// (Squid `dst`), anything else as a domain (Squid `dstdomain`).
func (h *BlacklistHandlers) AddDstAllow(w http.ResponseWriter, r *http.Request) {
	var item models.EgressAllowItem
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	entry := strings.TrimSpace(strings.ToLower(item.Entry))
	if entry == "" || strings.ContainsAny(entry, " ") {
		writeError(w, http.StatusBadRequest, "invalid entry")
		return
	}
	typ := "domain"
	if isValidCIDR(entry) || net.ParseIP(entry) != nil {
		typ = "cidr"
	} else if !strings.Contains(entry, ".") || strings.HasPrefix(entry, "-") {
		writeError(w, http.StatusBadRequest, "entry must be an IP, CIDR, or domain")
		return
	}
	_, err := h.db.Exec("INSERT INTO dst_allowlist(entry, type, description) VALUES(?,?,?)", entry, typ, item.Description)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusBadRequest, "entry already in allowlist")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	requestExport()
	if user, ok := r.Context().Value(middleware.CtxUsername).(string); ok {
		database.Audit(h.db, user, "add_egress_allowlist", entry, item.Description)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Entry added to egress allowlist"})
}

func (h *BlacklistHandlers) AddDomainWhitelist(w http.ResponseWriter, r *http.Request) {
	var item models.DomainListItem
	if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	domain := strings.TrimSpace(strings.ToLower(item.Domain))
	if domain == "" || strings.ContainsAny(domain, " ") {
		writeError(w, http.StatusBadRequest, "invalid domain format")
		return
	}
	entryType := "fqdn"
	for _, c := range []string{"*", "?", "[", "(", "|", "\\"} {
		if strings.Contains(domain, c) {
			entryType = "url-regex"
			break
		}
	}
	_, err := h.db.Exec("INSERT INTO domain_whitelist(domain, type, description) VALUES(?,?,?)", domain, entryType, item.Description)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusBadRequest, "domain already in whitelist")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": fmt.Sprintf("Domain added to whitelist (type: %s)", entryType)})
}

// ── Import ─────────────────────────────────────────────────────────────────────

// maxImportSize bounds a blacklist download. It is deliberately far below the
// container's memory limit (128M in both compose files): downloadWithRetry
// buffers the whole response and the parse then builds a dedupe set over it, so
// a cap above the budget means the process is OOM-killed before the cap can
// fire — the guard would read as protection and provide none (SECURE-INPT-01).
const maxImportSize = 32 * 1024 * 1024 // 32 MB

func (h *BlacklistHandlers) Import(w http.ResponseWriter, r *http.Request) {
	var req models.ImportBlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	blType := strings.ToLower(req.Type)
	if blType != "ip" && blType != "domain" {
		writeError(w, http.StatusBadRequest, "type must be 'ip' or 'domain'")
		return
	}

	var content string
	if req.URL != "" {
		// SSRF protection.
		if ssrf, err := isSSRFTarget(req.URL); err != nil || ssrf {
			if err != nil {
				writeError(w, http.StatusBadRequest, "URL validation failed: "+err.Error())
			} else {
				writeError(w, http.StatusForbidden, "requests to private/reserved networks are blocked")
			}
			return
		}
		body, err := downloadWithRetry(req.URL, maxImportSize)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to fetch URL: "+err.Error())
			return
		}
		content = string(body)
	} else if req.Content != "" {
		content = req.Content
	} else {
		writeError(w, http.StatusBadRequest, "either 'url' or 'content' must be provided")
		return
	}

	table := "ip_blacklist"
	col := "ip"
	if blType == "domain" {
		table = "domain_blacklist"
		col = "domain"
	}

	// Load existing entries — used for in-memory de-duplication of the
	// import. A scan failure means we silently lose track of an existing
	// row and may try to re-insert it (INSERT OR IGNORE saves us at the
	// SQL layer, but the resulting "added" counter will be wrong). Log
	// and surface a server error if we can't even open the cursor.
	existing := map[string]struct{}{}
	rows, err := h.db.Query(fmt.Sprintf("SELECT %s FROM %s", col, table))
	if err != nil {
		log.Error().Err(err).Str("table", table).Msg("import: cannot read existing entries")
		writeError(w, http.StatusInternalServerError, "database error reading existing entries")
		return
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			log.Warn().Err(err).Str("table", table).Msg("import: skipping malformed existing row in dedup scan")
			continue
		}
		existing[v] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		log.Warn().Err(err).Str("table", table).Msg("import: dedup cursor terminated with error — duplicate count may be off")
	}
	rows.Close()

	var toInsert [][2]string
	importDesc := "Imported on " + time.Now().Format("2006-01-02")
	added, skipped, bogonSkipped := 0, 0, 0
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}
		entry := parts[len(parts)-1]
		if blType == "ip" {
			if !isValidCIDR(entry) {
				skipped++
				continue
			}
			// Firehol/bogon feeds include RFC1918 + loopback ranges; importing
			// them into the source ip_blacklist would lock out the LAN clients.
			if isLANBogonCIDR(entry) {
				bogonSkipped++
				skipped++
				continue
			}
		} else {
			// Strip URL scheme.
			if strings.HasPrefix(entry, "http://") || strings.HasPrefix(entry, "https://") {
				u, err := url.Parse(entry)
				if err != nil || u.Host == "" {
					skipped++
					continue
				}
				entry = u.Host
			}
			if !strings.Contains(entry, ".") || strings.HasPrefix(entry, ".") || strings.HasSuffix(entry, ".") {
				skipped++
				continue
			}
		}
		if _, exists := existing[entry]; exists {
			skipped++
			continue
		}
		existing[entry] = struct{}{}
		toInsert = append(toInsert, [2]string{entry, importDesc})
		added++
	}

	// Batch insert: 5000 rows per transaction. Track per-statement failures
	// so the response counter reflects what actually landed in the DB.
	const batchSize = 5000
	insertFailed := 0
	for i := 0; i < len(toInsert); i += batchSize {
		end := i + batchSize
		if end > len(toInsert) {
			end = len(toInsert)
		}
		tx, err := h.db.Begin()
		if err != nil {
			log.Error().Err(err).Msg("batch insert begin failed")
			insertFailed += end - i
			continue
		}
		stmt, err := tx.Prepare(fmt.Sprintf("INSERT OR IGNORE INTO %s (%s, description) VALUES(?,?)", table, col))
		if err != nil {
			_ = tx.Rollback()
			log.Error().Err(err).Msg("batch insert prepare failed")
			insertFailed += end - i
			continue
		}
		for _, pair := range toInsert[i:end] {
			if _, err := stmt.Exec(pair[0], pair[1]); err != nil {
				insertFailed++
				log.Debug().Err(err).Str("entry", pair[0]).Msg("import: row insert failed")
			}
		}
		stmt.Close()
		if err := tx.Commit(); err != nil {
			_ = tx.Rollback()
			log.Error().Err(err).Msg("batch insert commit failed")
			insertFailed += end - i
		}
	}
	added -= insertFailed
	skipped += insertFailed
	if added > 0 {
		requestExport()
	}
	msg := fmt.Sprintf("Successfully imported %d entries (%d skipped/invalid)", added, skipped)
	if bogonSkipped > 0 {
		msg += fmt.Sprintf(" — %d private/bogon ranges were dropped (a source IP blacklist must not include LAN ranges)", bogonSkipped)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": msg,
		"data":    map[string]any{"added": added, "skipped": skipped, "bogon_skipped": bogonSkipped},
	})
}

// maxGeoCountries mirrors the bound declared on ImportGeoBlacklistRequest.
const maxGeoCountries = 50

func (h *BlacklistHandlers) ImportGeo(w http.ResponseWriter, r *http.Request) {
	var req models.ImportGeoBlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Countries) == 0 {
		writeError(w, http.StatusBadRequest, "countries list required")
		return
	}
	// Enforce the bound the model declares. Without it an authenticated caller
	// could post millions of entries and, since duplicates were not collapsed,
	// drive two 30s outbound fetches per element from inside the request
	// goroutine — an unbounded amplifier that never returns (SECURE-DOM-01).
	if len(req.Countries) > maxGeoCountries {
		writeError(w, http.StatusBadRequest,
			fmt.Sprintf("too many countries: %d (max %d)", len(req.Countries), maxGeoCountries))
		return
	}
	seen := make(map[string]struct{}, len(req.Countries))
	countries := make([]string, 0, len(req.Countries))
	for _, c := range req.Countries {
		cc := strings.ToLower(strings.TrimSpace(c))
		if cc == "" {
			continue
		}
		if _, dup := seen[cc]; dup {
			continue
		}
		seen[cc] = struct{}{}
		countries = append(countries, cc)
	}
	req.Countries = countries

	existing := map[string]struct{}{}
	rows, _ := h.db.Query("SELECT ip FROM ip_blacklist")
	if rows != nil {
		for rows.Next() {
			var v string
			rows.Scan(&v) //nolint:errcheck
			existing[v] = struct{}{}
		}
		rows.Close()
	}

	totalImported := 0
	importedCountries := 0
	var fetchErrors []string
	// SECURE-INPT-03. The default feeds are third-party hosts we do not control,
	// so a hijacked or compromised upstream must not be able to redirect us at
	// an internal address: those go through the SSRF-safe client, which
	// validates at dial time and on every redirect hop.
	//
	// An operator-supplied GEOIP_URL is a different case — pointing it at a
	// mirror on the LAN is a legitimate self-hosting configuration, and the
	// SSRF client would refuse exactly that. It gets a plain client with a
	// bounded redirect chain instead: the operator chose the endpoint, so the
	// address is their decision, but an unbounded redirect chain is not.
	var client *http.Client
	if h.cfg.GeoIPURL == "" {
		client = netguard.SSRFSafeClient()
	} else {
		client = &http.Client{
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("stopped after 5 redirects")
				}
				return nil
			},
		}
	}
	client.Timeout = 30 * time.Second

	ccRe := regexp.MustCompile(`^[a-zA-Z]{2}$`)
	for _, country := range req.Countries {
		cc := strings.ToLower(country)
		if !ccRe.MatchString(cc) {
			fetchErrors = append(fetchErrors, cc+": invalid country code")
			continue
		}
		urls := []string{}
		if h.cfg.GeoIPURL != "" {
			urls = append(urls, h.cfg.GeoIPURL+"?cc="+cc)
		} else {
			urls = append(urls,
				"https://www.ipdeny.com/ipblocks/data/countries/"+cc+".zone",
				"https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/"+cc+".cidr",
			)
		}
		var content string
		for _, u := range urls {
			resp, err := client.Get(u)
			if err == nil && resp.StatusCode == 200 {
				data, _ := readAll(resp.Body)
				resp.Body.Close()
				content = string(data)
				break
			}
			if resp != nil {
				resp.Body.Close()
			}
		}
		if content == "" {
			fetchErrors = append(fetchErrors, strings.ToUpper(cc)+": no data")
			continue
		}
		var toInsert [][2]string
		for _, line := range strings.Split(content, "\n") {
			ip := strings.TrimSpace(line)
			if ip == "" || strings.HasPrefix(ip, "#") {
				continue
			}
			// Same guards as the regular import: valid CIDR/IP, and never a
			// private/bogon range (the ip_blacklist is a source ACL).
			if !isValidCIDR(ip) || isLANBogonCIDR(ip) {
				continue
			}
			if _, ex := existing[ip]; !ex {
				toInsert = append(toInsert, [2]string{ip, "GeoIP: " + strings.ToUpper(cc)})
				existing[ip] = struct{}{}
			}
		}
		if len(toInsert) == 0 {
			continue
		}
		// Count rows that COMMITTED, not rows queued in memory. The previous
		// code incremented before any database work and discarded the errors
		// from Begin, Prepare, Exec and Commit, so a locked or read-only SQLite
		// produced a 200 reporting tens of thousands of imported blocks with
		// nothing written (SECURE-ERR-01).
		committed, err := insertGeoBatch(h.db, toInsert)
		if err != nil {
			// Roll the in-memory dedupe set back so a retry can re-attempt these.
			for _, pair := range toInsert {
				delete(existing, pair[0])
			}
			fetchErrors = append(fetchErrors, strings.ToUpper(cc)+": "+err.Error())
			continue
		}
		totalImported += committed
		importedCountries++
	}

	// A failure that imported nothing is a failure; a partial import must say
	// which countries failed rather than reporting an unqualified success.
	if totalImported == 0 && len(fetchErrors) > 0 {
		writeError(w, http.StatusBadGateway, strings.Join(fetchErrors, "; "))
		return
	}
	requestExport()
	resp := map[string]any{
		"status":  "success",
		"message": fmt.Sprintf("Imported %d IP blocks for %d of %d countries", totalImported, importedCountries, len(req.Countries)),
		"data":    map[string]any{"imported": totalImported, "countries_imported": importedCountries, "countries_requested": len(req.Countries)},
	}
	if len(fetchErrors) > 0 {
		resp["status"] = "partial"
		resp["data"].(map[string]any)["errors"] = fetchErrors
	}
	writeJSON(w, http.StatusOK, resp)
}

// insertGeoBatch writes one country's blocks in a single transaction and
// returns how many rows were actually committed. Every error is checked: the
// caller reports a count, and a count that is not backed by a commit is a lie.
func insertGeoBatch(db *sql.DB, rows [][2]string) (int, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck — no-op once committed

	stmt, err := tx.Prepare("INSERT INTO ip_blacklist(ip, description) VALUES(?,?)")
	if err != nil {
		return 0, fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	inserted := 0
	for _, pair := range rows {
		res, err := stmt.Exec(pair[0], pair[1])
		if err != nil {
			// A UNIQUE collision is expected (the row is already blacklisted)
			// and is not a batch failure; anything else is.
			if strings.Contains(err.Error(), "UNIQUE") {
				continue
			}
			return 0, fmt.Errorf("insert %s: %w", pair[0], err)
		}
		if n, err := res.RowsAffected(); err == nil {
			inserted += int(n)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return inserted, nil
}

// Legacy aliases — redirect to unified import endpoint.
func (h *BlacklistHandlers) ImportIPLegacy(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusGone, "Use POST /api/blacklists/import with type=ip instead")
}

func (h *BlacklistHandlers) ImportDomainLegacy(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusGone, "Use POST /api/blacklists/import with type=domain instead")
}

// ── propagate ─────────────────────────────────────────────────────────────────

// requestExport asks the owned exporter to publish the lists. It replaces the
// eight detached `go propagate(...)` spawns, which had no context, no owner, no
// concurrency bound and no way to report failure, and which ran the six-file
// export concurrently with itself (SECURE-CONC-03, SECURE-ERR-05).
func requestExport() { workers.RequestExport() }

func kindFromTable(table string) string {
	if strings.Contains(table, "domain") {
		return "domain"
	}
	return "ip"
}
