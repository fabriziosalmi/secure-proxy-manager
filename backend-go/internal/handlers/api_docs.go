package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

type APIDoc struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Auth   bool   `json:"auth"`
	Desc   string `json:"description"`
}

func RegisterAPIDocs(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.Get("/api/docs", func(w http.ResponseWriter, _ *http.Request) {
		docs := []APIDoc{
			// Health
			{Method: "GET", Path: "/api/health", Auth: false, Desc: "Health check — returns version, runtime, update/CVE info"},
			{Method: "GET", Path: "/health", Auth: false, Desc: "Legacy health check (simple)"},

			// Auth
			{Method: "POST", Path: "/api/auth/login", Auth: false, Desc: "JWT login — returns access_token"},
			{Method: "POST", Path: "/api/logout", Auth: true, Desc: "Invalidate current JWT token"},
			{Method: "POST", Path: "/api/change-password", Auth: true, Desc: "Change admin password (requires current_password + new_password)"},
			{Method: "GET", Path: "/api/ws-token", Auth: true, Desc: "Get one-time WebSocket auth token for live log streaming"},

			// Dashboard & Analytics
			{Method: "GET", Path: "/api/dashboard/summary", Auth: true, Desc: "Aggregated dashboard data (requests, blocks, top clients, threat categories, WAF stats)"},
			{Method: "GET", Path: "/api/status", Auth: true, Desc: "System status overview"},
			{Method: "GET", Path: "/api/traffic/statistics", Auth: true, Desc: "Traffic statistics by time period"},
			{Method: "GET", Path: "/api/clients/statistics", Auth: true, Desc: "Top 50 client IPs by request count"},
			{Method: "GET", Path: "/api/domains/statistics", Auth: true, Desc: "Top 50 domains with blocked/allowed status"},
			{Method: "GET", Path: "/api/cache/statistics", Auth: true, Desc: "Squid cache hit/miss statistics"},
			{Method: "GET", Path: "/api/waf/stats", Auth: true, Desc: "WAF engine stats (inspected, blocked, entropy, categories, cache)"},
			{Method: "GET", Path: "/api/analytics/shadow-it", Auth: true, Desc: "Detected SaaS services (35+ categories: file sharing, messaging, AI, social)"},
			{Method: "GET", Path: "/api/analytics/user-agents", Auth: true, Desc: "HTTP method + service type breakdown"},
			{Method: "GET", Path: "/api/analytics/file-extensions", Auth: true, Desc: "File extension distribution by category (Web, Images, Code, Archives)"},
			{Method: "GET", Path: "/api/analytics/top-domains", Auth: true, Desc: "Top 50 accessed domains (for word cloud)"},
			{Method: "GET", Path: "/api/security/score", Auth: true, Desc: "Security score 0-100 with recommendations"},
			{Method: "GET", Path: "/api/security/cve", Auth: true, Desc: "Known CVEs for installed Squid version"},
			{Method: "GET", Path: "/api/audit-log", Auth: true, Desc: "Admin action audit trail (who changed what, when)"},

			// Logs
			{Method: "GET", Path: "/api/logs", Auth: true, Desc: "Proxy access logs with pagination (?limit=25&offset=0&sort=timestamp&order=desc&search=...)"},
			{Method: "GET", Path: "/api/logs/stats", Auth: true, Desc: "Log statistics (total, blocked, IP blocks count)"},
			{Method: "GET", Path: "/api/logs/timeline", Auth: true, Desc: "Hourly traffic timeline (?hours=24)"},
			{Method: "POST", Path: "/api/logs/clear", Auth: true, Desc: "Delete all proxy logs"},
			{Method: "POST", Path: "/api/logs/clear-old", Auth: true, Desc: "Delete logs older than N days (?days=30)"},

			// IP Blacklist
			{Method: "GET", Path: "/api/ip-blacklist", Auth: true, Desc: "List IP blacklist (?page=1&page_size=50&search=...)"},
			{Method: "POST", Path: "/api/ip-blacklist", Auth: true, Desc: "Add IP to blacklist ({ip, description})"},
			{Method: "DELETE", Path: "/api/ip-blacklist/{id}", Auth: true, Desc: "Delete IP from blacklist by ID"},
			{Method: "POST", Path: "/api/ip-blacklist/bulk-delete", Auth: true, Desc: "Bulk delete IPs by ID array"},
			{Method: "DELETE", Path: "/api/ip-blacklist/clear-all", Auth: true, Desc: "Delete ALL IPs from blacklist"},

			// Domain Blacklist
			{Method: "GET", Path: "/api/domain-blacklist", Auth: true, Desc: "List domain blacklist (?page=1&page_size=50&search=...)"},
			{Method: "POST", Path: "/api/domain-blacklist", Auth: true, Desc: "Add domain to blacklist ({domain, description})"},
			{Method: "DELETE", Path: "/api/domain-blacklist/{id}", Auth: true, Desc: "Delete domain from blacklist by ID"},
			{Method: "POST", Path: "/api/domain-blacklist/bulk-delete", Auth: true, Desc: "Bulk delete domains by ID array"},
			{Method: "DELETE", Path: "/api/domain-blacklist/clear-all", Auth: true, Desc: "Delete ALL domains from blacklist"},

			// IP Whitelist
			{Method: "GET", Path: "/api/ip-whitelist", Auth: true, Desc: "List IP whitelist"},
			{Method: "POST", Path: "/api/ip-whitelist", Auth: true, Desc: "Add IP to whitelist ({ip, description})"},
			{Method: "DELETE", Path: "/api/ip-whitelist/{id}", Auth: true, Desc: "Delete IP from whitelist by ID"},

			// Domain Whitelist
			{Method: "GET", Path: "/api/domain-whitelist", Auth: true, Desc: "List domain whitelist"},
			{Method: "POST", Path: "/api/domain-whitelist", Auth: true, Desc: "Add domain to whitelist ({domain, description})"},
			{Method: "DELETE", Path: "/api/domain-whitelist/{id}", Auth: true, Desc: "Delete domain from whitelist by ID"},

			// Import
			{Method: "POST", Path: "/api/blacklists/import", Auth: true, Desc: "Import blacklist from URL or text ({type: 'ip'|'domain', url?, content?})"},
			{Method: "POST", Path: "/api/blacklists/import-geo", Auth: true, Desc: "Import geo-block by country codes ({countries: ['CN','RU']})"},

			// Settings
			{Method: "GET", Path: "/api/settings", Auth: true, Desc: "Get all settings as [{setting_name, setting_value}]"},
			{Method: "POST", Path: "/api/settings", Auth: true, Desc: "Bulk update settings ({key: value, ...})"},

			// Maintenance
			{Method: "GET", Path: "/api/maintenance/backup-config", Auth: true, Desc: "Export full config as JSON backup"},
			{Method: "POST", Path: "/api/maintenance/restore-config", Auth: true, Desc: "Restore config from JSON backup"},
			{Method: "POST", Path: "/api/maintenance/reload-config", Auth: true, Desc: "Regenerate Squid ACL files and signal reload"},
			{Method: "POST", Path: "/api/maintenance/reload-dns", Auth: true, Desc: "Regenerate dnsmasq blocklist and signal reload"},
			{Method: "POST", Path: "/api/maintenance/clear-cache", Auth: true, Desc: "Clear Squid proxy cache"},
			{Method: "GET", Path: "/api/security/download-ca", Auth: true, Desc: "Download SSL-Bump CA certificate (.pem)"},
			{Method: "GET", Path: "/api/maintenance/check-cert-security", Auth: true, Desc: "Check SSL certificate status and security"},

			// Database
			{Method: "GET", Path: "/api/database/size", Auth: true, Desc: "SQLite database file size"},
			{Method: "POST", Path: "/api/database/optimize", Auth: true, Desc: "Run VACUUM + REINDEX on database"},
			{Method: "GET", Path: "/api/database/stats", Auth: true, Desc: "Database table row counts"},
			{Method: "GET", Path: "/api/database/export", Auth: true, Desc: "Export all data as JSON"},
			{Method: "POST", Path: "/api/database/reset", Auth: true, Desc: "Reset database to defaults (destructive!)"},

			// Counters
			{Method: "POST", Path: "/api/counters/reset", Auth: true, Desc: "Reset all counters (logs + WAF stats)"},

			// Security
			{Method: "POST", Path: "/api/internal/alert", Auth: true, Desc: "Receive security alert from WAF/proxy"},
			{Method: "GET", Path: "/api/security/rate-limits", Auth: true, Desc: "View current rate limit state per IP"},
			{Method: "DELETE", Path: "/api/security/rate-limits/{ip}", Auth: true, Desc: "Clear rate limit for specific IP"},

			// WebSocket
			{Method: "GET", Path: "/api/ws/logs", Auth: false, Desc: "WebSocket: real-time log stream (requires ?token= from /api/ws-token)"},

			// Docs
			{Method: "GET", Path: "/api/docs", Auth: false, Desc: "This endpoint — API documentation"},
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status":    "success",
			"endpoints": len(docs),
			"data":      docs,
		})
	})
}
