package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/docker"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
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
			like := "%" + search + "%"
			db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s LIKE ? OR description LIKE ?", table, col), like, like).Scan(&total) //nolint:errcheck
			rows, err = db.Query(fmt.Sprintf("SELECT * FROM %s WHERE %s LIKE ? OR description LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?", table, col), like, like, limit, offset)
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
			go propagate(db, cfg, kindFromTable(table))
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
			go propagate(db, cfg, kindFromTable(table))
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
			go propagate(db, cfg, kindFromTable(table))
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
	_, err := h.db.Exec("INSERT INTO ip_blacklist(ip, description) VALUES(?,?)", ip, item.Description)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeError(w, http.StatusBadRequest, "IP address already in blacklist")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	go propagate(h.db, h.cfg, "ip")
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
	go propagate(h.db, h.cfg, "domain")
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Domain added to blacklist"})
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

const maxImportSize = 200 * 1024 * 1024 // 200 MB

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

	// Load existing entries.
	existing := map[string]struct{}{}
	rows, _ := h.db.Query(fmt.Sprintf("SELECT %s FROM %s", col, table))
	if rows != nil {
		for rows.Next() {
			var v string
			rows.Scan(&v) //nolint:errcheck
			existing[v] = struct{}{}
		}
		rows.Close()
	}

	var toInsert [][2]string
	added, skipped := 0, 0
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
		toInsert = append(toInsert, [2]string{entry, "Imported on " + time.Now().Format("2006-01-02")})
		added++
	}

	// Batch insert: 5000 rows per transaction.
	const batchSize = 5000
	for i := 0; i < len(toInsert); i += batchSize {
		end := i + batchSize
		if end > len(toInsert) {
			end = len(toInsert)
		}
		tx, err := h.db.Begin()
		if err != nil {
			log.Error().Err(err).Msg("batch insert begin failed")
			break
		}
		stmt, err := tx.Prepare(fmt.Sprintf("INSERT OR IGNORE INTO %s (%s, description) VALUES(?,?)", table, col))
		if err != nil {
			tx.Rollback()
			log.Error().Err(err).Msg("batch insert prepare failed")
			break
		}
		for _, pair := range toInsert[i:end] {
			stmt.Exec(pair[0], pair[1]) //nolint:errcheck
		}
		stmt.Close()
		if err := tx.Commit(); err != nil {
			tx.Rollback()
			log.Error().Err(err).Msg("batch insert commit failed")
		}
	}
	if added > 0 {
		go propagate(h.db, h.cfg, blType)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": fmt.Sprintf("Successfully imported %d entries (%d skipped/invalid)", added, skipped),
		"data":    map[string]any{"added": added, "skipped": skipped},
	})
}

func (h *BlacklistHandlers) ImportGeo(w http.ResponseWriter, r *http.Request) {
	var req models.ImportGeoBlacklistRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Countries) == 0 {
		writeError(w, http.StatusBadRequest, "countries list required")
		return
	}

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
	var fetchErrors []string
	client := &http.Client{Timeout: 30 * time.Second}

	for _, country := range req.Countries {
		cc := strings.ToLower(country)
		urls := []string{
			"https://www.ipdeny.com/ipblocks/data/countries/" + cc + ".zone",
			"https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/" + cc + ".cidr",
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
			if _, ex := existing[ip]; !ex {
				toInsert = append(toInsert, [2]string{ip, "GeoIP: " + strings.ToUpper(cc)})
				existing[ip] = struct{}{}
				totalImported++
			}
		}
		if len(toInsert) > 0 {
			tx, _ := h.db.Begin()
			stmt, _ := tx.Prepare("INSERT INTO ip_blacklist(ip, description) VALUES(?,?)")
			for _, pair := range toInsert {
				stmt.Exec(pair[0], pair[1]) //nolint:errcheck
			}
			stmt.Close()
			tx.Commit() //nolint:errcheck
		}
	}

	if len(fetchErrors) > 0 && totalImported == 0 {
		writeError(w, http.StatusBadGateway, strings.Join(fetchErrors, "; "))
		return
	}
	go propagate(h.db, h.cfg, "ip")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": fmt.Sprintf("Imported %d IP blocks for %d countries", totalImported, len(req.Countries)),
		"data":    map[string]any{"imported": totalImported},
	})
}

// Legacy aliases — redirect to unified import endpoint.
func (h *BlacklistHandlers) ImportIPLegacy(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusGone, "Use POST /api/blacklists/import with type=ip instead")
}

func (h *BlacklistHandlers) ImportDomainLegacy(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusGone, "Use POST /api/blacklists/import with type=domain instead")
}

// ── propagate ─────────────────────────────────────────────────────────────────

func propagate(db *sql.DB, cfg *config.Config, kind string) {
	if err := database.ExportBlacklistsToFiles(db, cfg.ConfigDir); err != nil {
		log.Warn().Err(err).Msg("export blacklists failed")
	}

	// Signal Squid to reload ACLs
	if kind == "ip" || kind == "all" {
		client := &http.Client{Timeout: 5 * time.Second}
		if resp, err := client.Post(fmt.Sprintf("http://%s:%s/api/reload", cfg.ProxyHost, cfg.ProxyPort), "application/json", nil); err == nil {
			resp.Body.Close()
		}
	}

	// Signal dnsmasq to reload blocklist (SIGHUP via Docker API)
	if kind == "domain" || kind == "all" {
		dc := docker.New()
		if err := dc.KillContainer("secure-proxy-manager-dns-1", "HUP"); err != nil {
			log.Warn().Err(err).Msg("dnsmasq SIGHUP failed (docker.sock mounted?)")
		} else {
			log.Info().Msg("dnsmasq reload signaled")
		}
	}
}

func kindFromTable(table string) string {
	if strings.Contains(table, "domain") {
		return "domain"
	}
	return "ip"
}
