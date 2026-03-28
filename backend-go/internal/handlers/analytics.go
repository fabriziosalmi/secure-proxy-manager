package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
)

type AnalyticsHandlers struct {
	db  *sql.DB
	cfg *config.Config
}

func NewAnalyticsHandlers(db *sql.DB, cfg *config.Config) *AnalyticsHandlers {
	return &AnalyticsHandlers{db: db, cfg: cfg}
}

func (h *AnalyticsHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Get("/api/status", h.Status)
	r.With(authMW).Get("/api/traffic/statistics", h.TrafficStats)
	r.With(authMW).Get("/api/clients/statistics", h.ClientStats)
	r.With(authMW).Get("/api/domains/statistics", h.DomainStats)
	r.With(authMW).Get("/api/cache/statistics", h.CacheStats)
	r.With(authMW).Get("/api/waf/stats", h.WAFStats)
	r.With(authMW).Get("/api/waf/categories", h.WAFCategories)
	r.With(authMW).Post("/api/waf/categories/toggle", h.WAFCategoryToggle)
	r.With(authMW).Post("/api/counters/reset", h.ResetCounters)
	r.With(authMW).Get("/api/dashboard/summary", h.DashboardSummary)
	r.With(authMW).Get("/api/analytics/shadow-it", h.ShadowIT)
	r.With(authMW).Get("/api/analytics/user-agents", h.UserAgents)
	r.With(authMW).Get("/api/analytics/file-extensions", h.FileExtensions)
	r.With(authMW).Get("/api/analytics/top-domains", h.TopDomains)
	r.With(authMW).Get("/api/audit-log", h.AuditLog)
	r.With(authMW).Post("/api/waf/test-rule", h.TestRule)
}

func (h *AnalyticsHandlers) Status(w http.ResponseWriter, r *http.Request) {
	proxyStatus := "error"
	client := &http.Client{Timeout: 1 * time.Second}
	resp, err := client.Get("http://" + h.cfg.ProxyHost + ":3128")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 400 {
			proxyStatus = "running"
		}
	}

	var todayCount int
	todayStr := time.Now().Format("2006-01-02")
	h.db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE timestamp >= ? AND timestamp < date(?, '+1 day')", todayStr, todayStr).Scan(&todayCount) //nolint:errcheck

	writeOK(w, map[string]any{
		"proxy_status":   proxyStatus,
		"proxy_host":     h.cfg.ProxyHost,
		"proxy_port":     "3128",
		"timestamp":      time.Now().Format(time.RFC3339),
		"version":        config.AppVersion,
		"requests_count": todayCount,
		"memory_usage":   "N/A",
		"cpu_usage":      "N/A",
		"uptime":         "N/A",
	})
}

func (h *AnalyticsHandlers) TrafficStats(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "day"
	}

	var interval, intervalFormat string
	var startDuration string
	switch period {
	case "hour":
		interval = `strftime('%Y-%m-%d %H:%M', timestamp)`
		intervalFormat = "2006-01-02 15:04"
		startDuration = "-1 hours"
	case "week":
		interval = `strftime('%Y-%m-%d', timestamp)`
		intervalFormat = "2006-01-02"
		startDuration = "-7 days"
	case "month":
		interval = `strftime('%Y-%m-%d', timestamp)`
		intervalFormat = "2006-01-02"
		startDuration = "-30 days"
	default: // "day"
		period = "day"
		interval = `strftime('%Y-%m-%d %H', timestamp)`
		intervalFormat = "2006-01-02 15"
		startDuration = "-1 days"
	}

	rows, err := h.db.Query(`
		SELECT `+interval+` AS bucket, COUNT(*) AS total,
		       SUM(CASE WHEN status LIKE '%DENIED%' OR status LIKE '%BLOCKED%' THEN 1 ELSE 0 END) AS blocked
		FROM proxy_logs WHERE timestamp >= datetime('now', ?) GROUP BY bucket`,
		startDuration,
	)
	bucketMap := map[string]map[string]int{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var bucket string
			var total, blocked int
			rows.Scan(&bucket, &total, &blocked) //nolint:errcheck
			bucketMap[bucket] = map[string]int{"total": total, "blocked": blocked}
		}
	}

	// Build labels array from now back.
	var labels []string
	var inbound, outbound, blocked []int
	now := time.Now()
	var step time.Duration
	var labelFmt string
	switch period {
	case "hour":
		step = 5 * time.Minute
		labelFmt = intervalFormat
	case "week":
		step = 24 * time.Hour
		labelFmt = intervalFormat
	case "month":
		step = 24 * time.Hour
		labelFmt = intervalFormat
	default:
		step = time.Hour
		labelFmt = intervalFormat
	}
	startT := now.Add(-parseDuration(startDuration))
	for t := startT; t.Before(now) || t.Equal(now); t = t.Add(step) {
		lbl := t.Format(labelFmt)
		labels = append(labels, lbl)
		if m, ok := bucketMap[lbl]; ok {
			inbound = append(inbound, m["total"])
			blocked = append(blocked, m["blocked"])
		} else {
			inbound = append(inbound, 0)
			blocked = append(blocked, 0)
		}
		outbound = append(outbound, 0)
	}
	writeOK(w, map[string]any{
		"labels": labels, "inbound": inbound, "outbound": outbound, "blocked": blocked,
	})
}

func parseDuration(s string) time.Duration {
	// Simple: "-1 hours" → 1h, "-7 days" → 7*24h, "-30 days" → 30*24h.
	if strings.HasSuffix(s, "hours") {
		return time.Hour
	}
	if strings.HasSuffix(s, "days") {
		if strings.HasPrefix(s, "-7") {
			return 7 * 24 * time.Hour
		}
		return 30 * 24 * time.Hour
	}
	return 24 * time.Hour
}

func (h *AnalyticsHandlers) ClientStats(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`
		SELECT source_ip, COUNT(*) AS requests FROM proxy_logs
		WHERE source_ip IS NOT NULL AND source_ip != ''
		GROUP BY source_ip ORDER BY requests DESC LIMIT 50`)
	if err != nil {
		writeOK(w, map[string]any{"total_clients": 0, "clients": []any{}})
		return
	}
	defer rows.Close()
	var clients []map[string]any
	for rows.Next() {
		var ip string
		var cnt int
		rows.Scan(&ip, &cnt) //nolint:errcheck
		clients = append(clients, map[string]any{"ip_address": ip, "requests": cnt, "status": "Active"})
	}
	if clients == nil {
		clients = []map[string]any{}
	}
	var total int
	h.db.QueryRow("SELECT COUNT(DISTINCT source_ip) FROM proxy_logs WHERE source_ip IS NOT NULL AND source_ip != ''").Scan(&total) //nolint:errcheck
	writeOK(w, map[string]any{"total_clients": total, "clients": clients})
}

func (h *AnalyticsHandlers) DomainStats(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`
		SELECT destination, COUNT(*) AS requests,
		       SUM(CASE WHEN status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%' THEN 1 ELSE 0 END) AS blocked_requests
		FROM proxy_logs WHERE destination IS NOT NULL AND destination != ''
		GROUP BY destination ORDER BY requests DESC LIMIT 50`)
	if err != nil {
		writeOK(w, []any{})
		return
	}
	defer rows.Close()

	blRows, _ := h.db.Query("SELECT domain FROM domain_blacklist")
	var blExact []string
	if blRows != nil {
		defer blRows.Close()
		for blRows.Next() {
			var d string
			blRows.Scan(&d) //nolint:errcheck
			blExact = append(blExact, d)
		}
	}
	blSet := map[string]struct{}{}
	var wildcards []string
	for _, d := range blExact {
		blSet[d] = struct{}{}
		if strings.HasPrefix(d, "*.") {
			wildcards = append(wildcards, d[2:])
		}
	}

	var domains []map[string]any
	for rows.Next() {
		var dest string
		var reqs, blkReqs int
		rows.Scan(&dest, &reqs, &blkReqs) //nolint:errcheck
		_, inSet := blSet[dest]
		isBlocked := inSet || blkReqs > 0
		if !isBlocked {
			for _, w := range wildcards {
				if strings.HasSuffix(dest, w) {
					isBlocked = true
					break
				}
			}
		}
		status := "Allowed"
		if isBlocked {
			status = "Blocked"
		}
		domains = append(domains, map[string]any{"domain_name": dest, "requests": reqs, "status": status})
	}
	if domains == nil {
		domains = []map[string]any{}
	}
	writeOK(w, domains)
}

func (h *AnalyticsHandlers) CacheStats(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{
		"hit_rate": 0, "byte_hit_rate": 0, "cache_size": "N/A",
		"max_cache_size": "N/A", "objects_cached": 0, "simulated": true,
	})
}

func (h *AnalyticsHandlers) WAFStats(w http.ResponseWriter, r *http.Request) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://waf:8080/stats")
	if err != nil {
		writeError(w, http.StatusBadGateway, "WAF service unreachable")
		return
	}
	defer resp.Body.Close()
	var data any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		writeError(w, http.StatusBadGateway, "invalid WAF stats response")
		return
	}
	writeOK(w, data)
}

func (h *AnalyticsHandlers) ResetCounters(w http.ResponseWriter, r *http.Request) {
	res, _ := h.db.Exec("DELETE FROM proxy_logs")
	deleted, _ := res.RowsAffected()

	client := &http.Client{Timeout: 3 * time.Second}
	wafReset := false
	if resp, err := client.Post("http://waf:8080/reset", "application/json", nil); err == nil {
		resp.Body.Close()
		wafReset = resp.StatusCode == 200
	}
	writeOK(w, map[string]any{"logs_cleared": deleted, "waf_reset": wafReset})
}

func (h *AnalyticsHandlers) DashboardSummary(w http.ResponseWriter, r *http.Request) {
	result := map[string]any{}

	var totalReqs, blockedReqs, todayReqs, todayBlocked, ipBLCount, domainBLCount int
	h.db.QueryRow("SELECT COUNT(*) FROM proxy_logs").Scan(&totalReqs)                                                                                  //nolint:errcheck
	h.db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%'").Scan(&blockedReqs) //nolint:errcheck

	today := time.Now().Format("2006-01-02")
	h.db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE timestamp >= ?", today).Scan(&todayReqs)                                                        //nolint:errcheck
	h.db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE (status LIKE '%DENIED%' OR status LIKE '%403%') AND timestamp >= ?", today).Scan(&todayBlocked) //nolint:errcheck

	result["total_requests"] = totalReqs
	result["blocked_requests"] = blockedReqs
	result["today_requests"] = todayReqs
	result["today_blocked"] = todayBlocked

	var topBlocked []map[string]any
	rows, _ := h.db.Query(`SELECT destination, COUNT(*) AS cnt FROM proxy_logs WHERE (status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%') AND timestamp >= datetime('now','-1 day') GROUP BY destination ORDER BY cnt DESC LIMIT 10`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var dest string
			var cnt int
			rows.Scan(&dest, &cnt) //nolint:errcheck
			topBlocked = append(topBlocked, map[string]any{"dest": dest, "count": cnt})
		}
	}
	if topBlocked == nil {
		topBlocked = []map[string]any{}
	}
	result["top_blocked"] = topBlocked

	h.db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&ipBLCount)         //nolint:errcheck
	h.db.QueryRow("SELECT COUNT(*) FROM domain_blacklist").Scan(&domainBLCount) //nolint:errcheck
	result["ip_blacklist_count"] = ipBLCount
	result["domain_blacklist_count"] = domainBLCount

	// Top clients (last 24h)
	var topClients []map[string]any
	cRows, _ := h.db.Query(`SELECT source_ip, COUNT(*) AS cnt FROM proxy_logs WHERE timestamp >= datetime('now','-1 day') AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY cnt DESC LIMIT 10`)
	if cRows != nil {
		defer cRows.Close()
		for cRows.Next() {
			var ip string
			var cnt int
			cRows.Scan(&ip, &cnt) //nolint:errcheck
			topClients = append(topClients, map[string]any{"ip": ip, "count": cnt})
		}
	}
	if topClients == nil { topClients = []map[string]any{} }
	result["top_clients"] = topClients

	// Threat categories (last 7 days)
	var threatCats []map[string]any
	tRows, _ := h.db.Query(`SELECT CASE WHEN destination LIKE '%.exe%' OR destination LIKE '%.dll%' THEN 'Malware' WHEN status LIKE '%DENIED%' AND destination LIKE '%:%' THEN 'Direct IP' WHEN status LIKE '%403%' THEN 'WAF Block' ELSE 'Policy' END as category, COUNT(*) as cnt FROM proxy_logs WHERE (status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%') AND timestamp >= datetime('now','-7 days') GROUP BY category ORDER BY cnt DESC`)
	if tRows != nil {
		defer tRows.Close()
		for tRows.Next() {
			var cat string
			var cnt int
			tRows.Scan(&cat, &cnt) //nolint:errcheck
			threatCats = append(threatCats, map[string]any{"category": cat, "count": cnt})
		}
	}
	if threatCats == nil { threatCats = []map[string]any{} }
	result["threat_categories"] = threatCats

	// Recent blocks (last 10)
	var recentBlocks []map[string]any
	rRows, _ := h.db.Query(`SELECT timestamp, source_ip, method, destination, status FROM proxy_logs WHERE status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%' ORDER BY id DESC LIMIT 10`)
	if rRows != nil {
		defer rRows.Close()
		for rRows.Next() {
			var ts, srcIP, method, dest, status string
			rRows.Scan(&ts, &srcIP, &method, &dest, &status) //nolint:errcheck
			recentBlocks = append(recentBlocks, map[string]any{
				"timestamp": ts, "source_ip": srcIP, "method": method,
				"destination": dest, "status": status,
			})
		}
	}
	if recentBlocks == nil { recentBlocks = []map[string]any{} }
	result["recent_blocks"] = recentBlocks

	// WAF stats
	client := &http.Client{Timeout: 2 * time.Second}
	if resp, err := client.Get("http://waf:8080/stats"); err == nil {
		var wafData any
		json.NewDecoder(resp.Body).Decode(&wafData) //nolint:errcheck
		resp.Body.Close()
		result["waf"] = wafData
	} else {
		result["waf"] = nil
	}
	writeOK(w, result)
}

// knownSaaS maps domain suffixes to service names.
var knownSaaS = map[string]string{
	"dropbox.com": "Dropbox", "wetransfer.com": "WeTransfer", "mega.nz": "Mega",
	"mediafire.com": "MediaFire", "sendspace.com": "SendSpace",
	"drive.google.com": "Google Drive", "onedrive.live.com": "OneDrive",
	"icloud.com": "iCloud", "box.com": "Box",
	"slack.com": "Slack", "discord.com": "Discord", "telegram.org": "Telegram",
	"web.whatsapp.com": "WhatsApp Web",
	"notion.so":        "Notion", "trello.com": "Trello", "asana.com": "Asana",
	"airtable.com": "Airtable", "monday.com": "Monday",
	"canva.com": "Canva", "figma.com": "Figma",
	"pastebin.com": "Pastebin", "hastebin.com": "Hastebin",
	"ngrok.io": "ngrok", "ngrok.com": "ngrok",
	"tailscale.com": "Tailscale", "zerotier.com": "ZeroTier",
	"anydesk.com": "AnyDesk", "teamviewer.com": "TeamViewer", "tor2web.org": "Tor2Web",
	"chatgpt.com": "ChatGPT", "claude.ai": "Claude", "gemini.google.com": "Gemini",
	"reddit.com": "Reddit", "facebook.com": "Facebook", "instagram.com": "Instagram",
	"tiktok.com": "TikTok", "twitter.com": "Twitter/X", "x.com": "Twitter/X",
	"youtube.com": "YouTube", "twitch.tv": "Twitch", "netflix.com": "Netflix",
	"spotify.com": "Spotify",
}

var saaS_categories = map[string][]string{
	"File Sharing": {"Dropbox", "WeTransfer", "Mega", "MediaFire", "SendSpace", "Google Drive", "OneDrive", "iCloud", "Box"},
	"Messaging":    {"Slack", "Discord", "Telegram", "WhatsApp Web"},
	"Productivity": {"Notion", "Trello", "Asana", "Airtable", "Monday", "Canva", "Figma"},
	"Paste/Code":   {"Pastebin", "Hastebin"},
	"Tunneling":    {"ngrok", "Tailscale", "ZeroTier", "AnyDesk", "TeamViewer", "Tor2Web"},
	"AI":           {"ChatGPT", "Claude", "Gemini"},
	"Social":       {"Reddit", "Facebook", "Instagram", "TikTok", "Twitter/X", "YouTube", "Twitch"},
	"Streaming":    {"Netflix", "Spotify"},
}

func (h *AnalyticsHandlers) ShadowIT(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`
		SELECT destination, COUNT(*) AS cnt FROM proxy_logs
		WHERE destination IS NOT NULL AND destination != ''
		AND timestamp >= datetime('now', '-7 days')
		GROUP BY destination ORDER BY cnt DESC LIMIT 500`)
	if err != nil {
		writeOK(w, []any{})
		return
	}
	defer rows.Close()

	type entry struct {
		Name     string `json:"name"`
		Domain   string `json:"domain"`
		Requests int    `json:"requests"`
		Category string `json:"category"`
	}
	services := map[string]*entry{}

	for rows.Next() {
		var dest string
		var cnt int
		rows.Scan(&dest, &cnt) //nolint:errcheck
		domain := extractDomain(dest)
		for saasDomain, saasName := range knownSaaS {
			if domain == saasDomain || strings.HasSuffix(domain, "."+saasDomain) {
				if _, ok := services[saasName]; !ok {
					services[saasName] = &entry{Name: saasName, Domain: saasDomain, Category: "unknown"}
				}
				services[saasName].Requests += cnt
				break
			}
		}
	}

	// Assign categories.
	for cat, names := range saaS_categories {
		for _, name := range names {
			if e, ok := services[name]; ok {
				e.Category = cat
			}
		}
	}

	var result []*entry
	for _, e := range services {
		result = append(result, e)
	}
	// Simple sort by requests descending.
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Requests > result[i].Requests {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	if result == nil {
		result = []*entry{}
	}
	writeOK(w, result)
}

func (h *AnalyticsHandlers) UserAgents(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`
		SELECT method, COUNT(*) AS cnt FROM proxy_logs
		WHERE method IS NOT NULL AND method != '' AND method != '-'
		AND timestamp >= datetime('now', '-7 days')
		GROUP BY method ORDER BY cnt DESC`)
	var methods []map[string]any
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var m string
			var cnt int
			rows.Scan(&m, &cnt) //nolint:errcheck
			methods = append(methods, map[string]any{"name": m, "count": cnt})
		}
	}
	if methods == nil {
		methods = []map[string]any{}
	}
	writeOK(w, map[string]any{"methods": methods})
}

var extRe = regexp.MustCompile(`\.([a-zA-Z0-9]{1,10})(?:\?|$|#)`)

func (h *AnalyticsHandlers) FileExtensions(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`SELECT destination FROM proxy_logs WHERE destination IS NOT NULL AND destination != '' AND timestamp >= datetime('now', '-7 days')`)
	skipTLDs := map[string]struct{}{"com": {}, "net": {}, "org": {}, "io": {}, "dev": {}, "app": {}, "me": {}, "co": {}}
	extCounts := map[string]int{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var dest string
			rows.Scan(&dest) //nolint:errcheck
			path := strings.SplitN(dest, "?", 2)[0]
			path = strings.SplitN(path, "#", 2)[0]
			if m := extRe.FindStringSubmatch(path); len(m) > 1 {
				ext := strings.ToLower(m[1])
				if _, skip := skipTLDs[ext]; !skip {
					extCounts[ext]++
				}
			}
		}
	}
	var exts []map[string]any
	for e, c := range extCounts {
		exts = append(exts, map[string]any{"ext": "." + e, "count": c})
	}
	writeOK(w, map[string]any{"extensions": exts})
}

func (h *AnalyticsHandlers) TopDomains(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`
		SELECT destination, COUNT(*) AS cnt FROM proxy_logs
		WHERE destination IS NOT NULL AND destination != ''
		AND timestamp >= datetime('now', '-7 days')
		GROUP BY destination ORDER BY cnt DESC LIMIT 200`)
	domainCounts := map[string]int{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var dest string
			var cnt int
			rows.Scan(&dest, &cnt) //nolint:errcheck
			dom := extractDomain(dest)
			parts := strings.Split(dom, ".")
			var root string
			if len(parts) >= 2 {
				root = strings.Join(parts[len(parts)-2:], ".")
			} else {
				root = dom
			}
			domainCounts[root] += cnt
		}
	}
	if log.Trace().Enabled() {
		log.Trace().Int("domains", len(domainCounts)).Msg("top-domains computed")
	}
	var result []map[string]any
	for d, c := range domainCounts {
		result = append(result, map[string]any{"domain": d, "count": c})
	}
	writeOK(w, result)
}

func (h *AnalyticsHandlers) AuditLog(w http.ResponseWriter, r *http.Request) {
	limit := clamp(queryInt(r, "limit", 50), 1, 200)
	offset := max0(queryInt(r, "offset", 0))
	var total int
	h.db.QueryRow("SELECT COUNT(*) FROM audit_log").Scan(&total) //nolint:errcheck
	rows, err := h.db.Query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var entries []map[string]any
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
		entries = append(entries, row)
	}
	if entries == nil {
		entries = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "success", "data": entries, "total": total, "limit": limit, "offset": offset,
	})
}

// WAFCategories proxies GET /categories from the WAF container.
func (h *AnalyticsHandlers) WAFCategories(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get("http://waf:8080/categories")
	if err != nil {
		writeError(w, http.StatusBadGateway, "WAF unreachable")
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// WAFCategoryToggle proxies POST /categories/toggle to WAF.
func (h *AnalyticsHandlers) WAFCategoryToggle(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Post("http://waf:8080/categories/toggle", "application/json", r.Body)
	if err != nil {
		writeError(w, http.StatusBadGateway, "WAF unreachable")
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// TestRule tests a regex against recent proxy logs (Regex Playground).
func (h *AnalyticsHandlers) TestRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Regex string `json:"regex"`
		Hours int    `json:"hours"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Regex == "" {
		writeError(w, http.StatusBadRequest, "regex is required")
		return
	}
	if req.Hours <= 0 || req.Hours > 168 {
		req.Hours = 24
	}

	// Compile regex — if invalid, return error immediately
	re, err := regexp.Compile(req.Regex)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid regex: "+err.Error())
		return
	}

	// Query recent destinations from logs
	rows, err := h.db.Query(
		"SELECT destination FROM proxy_logs WHERE timestamp >= datetime('now', ? || ' hours') AND destination IS NOT NULL AND destination != '' LIMIT 10000",
		fmt.Sprintf("-%d", req.Hours),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	var matches []string
	var scanned int
	for rows.Next() {
		var dest string
		rows.Scan(&dest) //nolint:errcheck
		scanned++
		if re.MatchString(dest) {
			if len(matches) < 50 { // cap at 50 examples
				matches = append(matches, dest)
			}
		}
	}

	writeOK(w, map[string]any{
		"regex":     req.Regex,
		"hours":     req.Hours,
		"scanned":   scanned,
		"matched":   len(matches),
		"examples":  matches,
		"would_block": len(matches) > 0,
	})
}
