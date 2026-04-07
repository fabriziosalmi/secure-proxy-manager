package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	appMW "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
)

// wafBreaker protects against cascading failures when the WAF service is down.
var wafBreaker = appMW.NewCircuitBreaker(3, 30*time.Second)

// Shared HTTP clients — reused across requests to avoid per-request allocation.
var (
	wafClient   = &http.Client{Timeout: 3 * time.Second}
	probeClient = &http.Client{Timeout: 1 * time.Second}
)

// dockerExecer is the subset of docker.DockerClient needed for cache stats.
type dockerExecer interface {
	ExecContainer(name string, cmd []string) (string, error)
}

type AnalyticsHandlers struct {
	db     *sql.DB
	cfg    *config.Config
	docker dockerExecer
}

func NewAnalyticsHandlers(db *sql.DB, cfg *config.Config, dc dockerExecer) *AnalyticsHandlers {
	return &AnalyticsHandlers{db: db, cfg: cfg, docker: dc}
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
	resp, err := probeClient.Get(h.cfg.ProxyURL)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 400 || resp.StatusCode == 200 {
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

	// #nosec G202
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
	// Parse "-N hours" or "-N days" into Go duration.
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "-")
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return 24 * time.Hour
	}
	n := 1
	fmt.Sscanf(parts[0], "%d", &n)
	if n < 1 {
		n = 1
	}
	switch {
	case strings.HasPrefix(parts[1], "hour"):
		return time.Duration(n) * time.Hour
	case strings.HasPrefix(parts[1], "day"):
		return time.Duration(n) * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
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

	type logEntry struct {
		dest    string
		reqs    int
		blkReqs int
	}
	var entries []logEntry
	for rows.Next() {
		var dest string
		var reqs, blkReqs int
		rows.Scan(&dest, &reqs, &blkReqs) //nolint:errcheck
		entries = append(entries, logEntry{dest, reqs, blkReqs})
	}
	rows.Close()

	blRows, _ := h.db.Query("SELECT domain FROM domain_blacklist")
	blSet := map[string]struct{}{}
	var wildcards []string
	if blRows != nil {
		for blRows.Next() {
			var d string
			blRows.Scan(&d) //nolint:errcheck
			blSet[d] = struct{}{}
			if strings.HasPrefix(d, "*.") {
				wildcards = append(wildcards, d[2:])
			}
		}
		blRows.Close()
	}

	var domains []map[string]any
	for _, e := range entries {
		_, inSet := blSet[e.dest]
		isBlocked := inSet || e.blkReqs > 0
		if !isBlocked {
			for _, w := range wildcards {
				if strings.HasSuffix(e.dest, w) {
					isBlocked = true
					break
				}
			}
		}
		status := "Allowed"
		if isBlocked {
			status = "Blocked"
		}
		domains = append(domains, map[string]any{"domain_name": e.dest, "requests": e.reqs, "status": status})
	}
	if domains == nil {
		domains = []map[string]any{}
	}
	writeOK(w, domains)
}

func (h *AnalyticsHandlers) CacheStats(w http.ResponseWriter, r *http.Request) {
	out, err := h.docker.ExecContainer("secure-proxy-manager-proxy", []string{"squidclient", "-h", "127.0.0.1", "-p", "3128", "mgr:info"})
	if err != nil {
		log.Debug().Err(err).Msg("squidclient mgr:info failed, returning zeros")
		writeOK(w, map[string]any{
			"hit_rate": 0, "byte_hit_rate": 0, "cache_size": "N/A",
			"max_cache_size": "N/A", "objects_cached": 0, "hits": 0,
			"misses": 0, "requests": 0, "simulated": true,
		})
		return
	}
	writeOK(w, parseSquidInfo(out))
}

// parseSquidInfo extracts cache metrics from squidclient mgr:info output.
func parseSquidInfo(raw string) map[string]any {
	result := map[string]any{
		"hit_rate": 0.0, "byte_hit_rate": 0.0, "cache_size": "N/A",
		"max_cache_size": "N/A", "objects_cached": 0, "hits": 0,
		"misses": 0, "requests": 0, "bytes_saved": 0, "simulated": false,
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Request Hit Ratios:"):
			// "Request Hit Ratios:     5min: 42.3%, 60min: 38.1%"
			if parts := strings.SplitN(line, "5min:", 2); len(parts) == 2 {
				val := strings.TrimSpace(strings.SplitN(parts[1], "%", 2)[0])
				if f, err := strconv.ParseFloat(val, 64); err == nil {
					result["hit_rate"] = f / 100
				}
			}
		case strings.HasPrefix(line, "Byte Hit Ratios:"):
			if parts := strings.SplitN(line, "5min:", 2); len(parts) == 2 {
				val := strings.TrimSpace(strings.SplitN(parts[1], "%", 2)[0])
				if f, err := strconv.ParseFloat(val, 64); err == nil {
					result["byte_hit_rate"] = f / 100
				}
			}
		case strings.HasPrefix(line, "Storage Swap size:"):
			// "Storage Swap size:	1234 KB"
			result["cache_size"] = strings.TrimSpace(strings.TrimPrefix(line, "Storage Swap size:"))
		case strings.HasPrefix(line, "Maximum Swap Size:"):
			result["max_cache_size"] = strings.TrimSpace(strings.TrimPrefix(line, "Maximum Swap Size:"))
		case strings.HasPrefix(line, "StoreEntries"):
			// "StoreEntries                : 1234"
			if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
				val := strings.TrimSpace(parts[1])
				if n, err := strconv.Atoi(val); err == nil {
					result["objects_cached"] = n
				}
			}
		case strings.Contains(line, "client_http.requests"):
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					result["requests"] = n
				}
			}
		case strings.Contains(line, "client_http.hits"):
			if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
				if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					result["hits"] = n
				}
			}
		case strings.Contains(line, "client_http.errors"):
			// use as proxy for misses (hits + misses ≈ requests)
		case strings.Contains(line, "Number of clients accessing cache:"):
			// optional metric
		}
	}
	// Compute misses from requests - hits
	if reqs, ok := result["requests"].(int); ok {
		if hits, ok := result["hits"].(int); ok {
			result["misses"] = reqs - hits
			if reqs > 0 {
				result["hit_ratio"] = float64(hits) / float64(reqs)
			}
		}
	}
	return result
}

func (h *AnalyticsHandlers) WAFStats(w http.ResponseWriter, r *http.Request) {
	if err := wafBreaker.Allow(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "WAF service circuit open — retrying soon")
		return
	}
	resp, err := wafClient.Get(h.cfg.WAFURL + "/stats")
	if err != nil {
		wafBreaker.RecordFailure()
		writeError(w, http.StatusBadGateway, "WAF service unreachable")
		return
	}
	defer resp.Body.Close()
	wafBreaker.RecordSuccess()
	var data any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		writeError(w, http.StatusBadGateway, "invalid WAF stats response")
		return
	}
	writeOK(w, data)
}

func (h *AnalyticsHandlers) ResetCounters(w http.ResponseWriter, r *http.Request) {
	res, err := h.db.Exec("DELETE FROM proxy_logs")
	var deleted int64
	if err == nil && res != nil {
		deleted, _ = res.RowsAffected()
	}

	wafReset := false
	if resp, err := wafClient.Post(h.cfg.WAFURL+"/reset", "application/json", nil); err == nil {
		resp.Body.Close()
		wafReset = resp.StatusCode == 200
	}
	writeOK(w, map[string]any{"logs_cleared": deleted, "waf_reset": wafReset})
}

func (h *AnalyticsHandlers) DashboardSummary(w http.ResponseWriter, r *http.Request) {
	result := map[string]any{}

	today := time.Now().Format("2006-01-02")
	var totalReqs, blockedReqs, todayReqs, todayBlocked int
	h.db.QueryRow(`SELECT
		COUNT(*),
		SUM(CASE WHEN status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%' THEN 1 ELSE 0 END),
		SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END),
		SUM(CASE WHEN (status LIKE '%DENIED%' OR status LIKE '%403%') AND timestamp >= ? THEN 1 ELSE 0 END)
		FROM proxy_logs`, today, today).Scan(&totalReqs, &blockedReqs, &todayReqs, &todayBlocked) //nolint:errcheck

	var ipBLCount, domainBLCount int

	result["total_requests"] = totalReqs
	result["blocked_requests"] = blockedReqs
	result["today_requests"] = todayReqs
	result["today_blocked"] = todayBlocked

	var topBlocked []map[string]any
	rows, _ := h.db.Query(`SELECT destination, COUNT(*) AS cnt FROM proxy_logs WHERE (status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%') AND timestamp >= datetime('now','-1 day') GROUP BY destination ORDER BY cnt DESC LIMIT 10`)
	if rows != nil {
		for rows.Next() {
			var dest string
			var cnt int
			rows.Scan(&dest, &cnt) //nolint:errcheck
			topBlocked = append(topBlocked, map[string]any{"dest": dest, "count": cnt})
		}
		rows.Close()
	}
	if topBlocked == nil {
		topBlocked = []map[string]any{}
	}
	result["top_blocked"] = topBlocked

	h.db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&ipBLCount)         //nolint:errcheck
	h.db.QueryRow("SELECT COUNT(*) FROM domain_blacklist").Scan(&domainBLCount) //nolint:errcheck
	// Note: these two are on different tables so cannot be combined into the proxy_logs query above.
	result["ip_blacklist_count"] = ipBLCount
	result["domain_blacklist_count"] = domainBLCount

	// Top clients (last 24h)
	var topClients []map[string]any
	cRows, _ := h.db.Query(`SELECT source_ip, COUNT(*) AS cnt FROM proxy_logs WHERE timestamp >= datetime('now','-1 day') AND source_ip IS NOT NULL AND source_ip != '' GROUP BY source_ip ORDER BY cnt DESC LIMIT 10`)
	if cRows != nil {
		for cRows.Next() {
			var ip string
			var cnt int
			cRows.Scan(&ip, &cnt) //nolint:errcheck
			topClients = append(topClients, map[string]any{"ip": ip, "count": cnt})
		}
		cRows.Close()
	}
	if topClients == nil {
		topClients = []map[string]any{}
	}
	result["top_clients"] = topClients

	// Threat categories (last 7 days)
	var threatCats []map[string]any
	tRows, _ := h.db.Query(`SELECT CASE WHEN destination LIKE '%.exe%' OR destination LIKE '%.dll%' THEN 'Malware' WHEN status LIKE '%DENIED%' AND destination LIKE '%:%' THEN 'Direct IP' WHEN status LIKE '%403%' THEN 'WAF Block' ELSE 'Policy' END as category, COUNT(*) as cnt FROM proxy_logs WHERE (status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%') AND timestamp >= datetime('now','-7 days') GROUP BY category ORDER BY cnt DESC`)
	if tRows != nil {
		for tRows.Next() {
			var cat string
			var cnt int
			tRows.Scan(&cat, &cnt) //nolint:errcheck
			threatCats = append(threatCats, map[string]any{"category": cat, "count": cnt})
		}
		tRows.Close()
	}
	if threatCats == nil {
		threatCats = []map[string]any{}
	}
	result["threat_categories"] = threatCats

	// Recent blocks (last 10)
	var recentBlocks []map[string]any
	rRows, _ := h.db.Query(`SELECT timestamp, source_ip, method, destination, status FROM proxy_logs WHERE status LIKE '%DENIED%' OR status LIKE '%403%' OR status LIKE '%BLOCKED%' ORDER BY id DESC LIMIT 10`)
	if rRows != nil {
		for rRows.Next() {
			var ts, srcIP, method, dest, status string
			rRows.Scan(&ts, &srcIP, &method, &dest, &status) //nolint:errcheck
			recentBlocks = append(recentBlocks, map[string]any{
				"timestamp": ts, "source_ip": srcIP, "method": method,
				"destination": dest, "status": status,
			})
		}
		rRows.Close()
	}
	if recentBlocks == nil {
		recentBlocks = []map[string]any{}
	}
	result["recent_blocks"] = recentBlocks

	// WAF stats
	if resp, err := wafClient.Get(h.cfg.WAFURL + "/stats"); err == nil {
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
	sort.Slice(result, func(i, j int) bool {
		return result[i].Requests > result[j].Requests
	})
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
		GROUP BY method ORDER BY cnt DESC LIMIT 50`)
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
	rows, err := h.db.Query(`SELECT destination FROM proxy_logs WHERE destination IS NOT NULL AND destination != '' AND timestamp >= datetime('now', '-7 days') LIMIT 10000`)
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
	if err := wafBreaker.Allow(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "WAF circuit open")
		return
	}
	resp, err := wafClient.Get(h.cfg.WAFURL + "/categories")
	if err != nil {
		wafBreaker.RecordFailure()
		writeError(w, http.StatusBadGateway, "WAF unreachable")
		return
	}
	wafBreaker.RecordSuccess()
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// WAFCategoryToggle proxies POST /categories/toggle to WAF.
func (h *AnalyticsHandlers) WAFCategoryToggle(w http.ResponseWriter, r *http.Request) {
	if err := wafBreaker.Allow(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "WAF circuit open")
		return
	}
	resp, err := wafClient.Post(h.cfg.WAFURL+"/categories/toggle", "application/json", r.Body)
	if err != nil {
		wafBreaker.RecordFailure()
		writeError(w, http.StatusBadGateway, "WAF unreachable")
		return
	}
	wafBreaker.RecordSuccess()
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
	if len(req.Regex) > 1024 {
		writeError(w, http.StatusBadRequest, "regex too long (max 1024 chars)")
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
		"regex":       req.Regex,
		"hours":       req.Hours,
		"scanned":     scanned,
		"matched":     len(matches),
		"examples":    matches,
		"would_block": len(matches) > 0,
	})
}
