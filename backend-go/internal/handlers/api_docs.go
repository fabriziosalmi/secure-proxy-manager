package handlers

import (
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
)

// APIDoc is one entry in the published API catalogue.
type APIDoc struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Auth   bool   `json:"auth"`
	Desc   string `json:"description"`
}

type docMeta struct {
	auth bool
	desc string
}

// routeDocs carries the human-written description for each route. It is only
// metadata: the CATALOGUE itself is walked from the live router, so a route can
// never be missing from /api/docs, only undescribed. The previous hand-written
// slice had drifted to 63 entries against 81 registered routes, silently
// omitting the whole egress-allowlist resource and POST /api/auth/refresh —
// the call a non-browser client needs to stay authenticated (SECURE-API-01).
var routeDocs = map[string]docMeta{
	"GET /api/analytics/file-extensions":       {auth: true, desc: "File extension distribution by category (Web, Images, Code, Archives)"},
	"GET /api/analytics/shadow-it":             {auth: true, desc: "Detected SaaS services (35+ categories: file sharing, messaging, AI, social)"},
	"GET /api/analytics/top-domains":           {auth: true, desc: "Top 50 accessed domains (for word cloud)"},
	"GET /api/analytics/user-agents":           {auth: true, desc: "HTTP method + service type breakdown"},
	"GET /api/audit-log":                       {auth: true, desc: "Admin action audit trail (who changed what, when)"},
	"POST /api/auth/login":                     {auth: false, desc: "JWT login — returns access_token"},
	"POST /api/blacklists/import":              {auth: true, desc: "Import blacklist from URL or text ({type: 'ip'|'domain', url?, content?})"},
	"POST /api/blacklists/import-geo":          {auth: true, desc: "Import geo-block by country codes ({countries: ['CN','RU']})"},
	"GET /api/cache/statistics":                {auth: true, desc: "Squid cache hit/miss statistics"},
	"POST /api/change-password":                {auth: true, desc: "Change admin password (requires current_password + new_password)"},
	"GET /api/clients/statistics":              {auth: true, desc: "Top 50 client IPs by request count"},
	"POST /api/counters/reset":                 {auth: true, desc: "Reset all counters (logs + WAF stats)"},
	"GET /api/dashboard/summary":               {auth: true, desc: "Aggregated dashboard data (requests, blocks, top clients, threat categories, WAF stats)"},
	"GET /api/database/export":                 {auth: true, desc: "Export all data as JSON"},
	"POST /api/database/optimize":              {auth: true, desc: "Run VACUUM + REINDEX on database"},
	"POST /api/database/reset":                 {auth: true, desc: "Reset database to defaults (destructive!)"},
	"GET /api/database/size":                   {auth: true, desc: "SQLite database file size"},
	"GET /api/database/stats":                  {auth: true, desc: "Database table row counts"},
	"GET /api/docs":                            {auth: false, desc: "This endpoint — API documentation"},
	"GET /api/domain-blacklist":                {auth: true, desc: "List domain blacklist (?page=1&page_size=50&search=...)"},
	"POST /api/domain-blacklist":               {auth: true, desc: "Add domain to blacklist ({domain, description})"},
	"POST /api/domain-blacklist/bulk-delete":   {auth: true, desc: "Bulk delete domains by ID array"},
	"DELETE /api/domain-blacklist/clear-all":   {auth: true, desc: "Delete ALL domains from blacklist"},
	"DELETE /api/domain-blacklist/{id}":        {auth: true, desc: "Delete domain from blacklist by ID"},
	"GET /api/domain-whitelist":                {auth: true, desc: "List domain whitelist"},
	"POST /api/domain-whitelist":               {auth: true, desc: "Add domain to whitelist ({domain, description})"},
	"DELETE /api/domain-whitelist/{id}":        {auth: true, desc: "Delete domain from whitelist by ID"},
	"GET /api/domains/statistics":              {auth: true, desc: "Top 50 domains with blocked/allowed status"},
	"GET /api/health":                          {auth: false, desc: "Health check — returns version, runtime, update/CVE info"},
	"POST /api/internal/alert":                 {auth: true, desc: "Receive security alert from WAF/proxy"},
	"GET /api/ip-blacklist":                    {auth: true, desc: "List IP blacklist (?page=1&page_size=50&search=...)"},
	"POST /api/ip-blacklist":                   {auth: true, desc: "Add IP to blacklist ({ip, description})"},
	"POST /api/ip-blacklist/bulk-delete":       {auth: true, desc: "Bulk delete IPs by ID array"},
	"DELETE /api/ip-blacklist/clear-all":       {auth: true, desc: "Delete ALL IPs from blacklist"},
	"DELETE /api/ip-blacklist/{id}":            {auth: true, desc: "Delete IP from blacklist by ID"},
	"GET /api/ip-whitelist":                    {auth: true, desc: "List IP whitelist"},
	"POST /api/ip-whitelist":                   {auth: true, desc: "Add IP to whitelist ({ip, description})"},
	"DELETE /api/ip-whitelist/{id}":            {auth: true, desc: "Delete IP from whitelist by ID"},
	"POST /api/logout":                         {auth: true, desc: "Invalidate current JWT token"},
	"GET /api/logs":                            {auth: true, desc: "Proxy access logs with pagination (?limit=25&offset=0&sort=timestamp&order=desc&search=...)"},
	"POST /api/logs/clear":                     {auth: true, desc: "Delete all proxy logs"},
	"POST /api/logs/clear-old":                 {auth: true, desc: "Delete logs older than N days (?days=30)"},
	"GET /api/logs/stats":                      {auth: true, desc: "Log statistics (total, blocked, IP blocks count)"},
	"GET /api/logs/timeline":                   {auth: true, desc: "Hourly traffic timeline (?hours=24)"},
	"GET /api/maintenance/backup-config":       {auth: true, desc: "Export full config as JSON backup"},
	"GET /api/maintenance/check-cert-security": {auth: true, desc: "Check SSL certificate status and security"},
	"POST /api/maintenance/clear-cache":        {auth: true, desc: "Clear Squid proxy cache"},
	"POST /api/maintenance/reload-config":      {auth: true, desc: "Regenerate Squid ACL files and signal reload"},
	"POST /api/maintenance/reload-dns":         {auth: true, desc: "Regenerate dnsmasq blocklist and signal reload"},
	"POST /api/maintenance/restore-config":     {auth: true, desc: "Restore config from JSON backup"},
	"GET /api/security/cve":                    {auth: true, desc: "Known CVEs for installed Squid version"},
	"GET /api/security/download-ca":            {auth: true, desc: "Download SSL-Bump CA certificate (.pem)"},
	"GET /api/security/rate-limits":            {auth: true, desc: "View current rate limit state per IP"},
	"DELETE /api/security/rate-limits/{ip}":    {auth: true, desc: "Clear rate limit for specific IP"},
	"GET /api/security/score":                  {auth: true, desc: "Security score 0-100 with recommendations"},
	"GET /api/settings":                        {auth: true, desc: "Get all settings as [{setting_name, setting_value}]"},
	"POST /api/settings":                       {auth: true, desc: "Bulk update settings ({key: value, ...})"},
	"GET /api/status":                          {auth: true, desc: "System status overview"},
	"GET /api/traffic/statistics":              {auth: true, desc: "Traffic statistics by time period"},
	"GET /api/waf/stats":                       {auth: true, desc: "WAF engine stats (inspected, blocked, entropy, categories, cache)"},
	"GET /api/ws-token":                        {auth: true, desc: "Get one-time WebSocket auth token for live log streaming"},
	"GET /api/ws/logs":                         {auth: false, desc: "WebSocket: real-time log stream (pass token from /api/ws-token as WebSocket subprotocol: spm-ws-token.<token>)"},
	"GET /health":                              {auth: false, desc: "Legacy health check (simple)"},
}

// publicRoutes are reachable without authentication. Kept explicit so the
// catalogue reports the auth requirement from one reviewable list rather than
// from a flag copied per entry.
var publicRoutes = map[string]bool{
	"POST /api/auth/login":   true,
	"POST /api/auth/refresh": true,
	"GET /api/docs":          true,
	"GET /api/health":        true,
	"GET /api/ready":         true,
	"GET /health":            true,
	"GET /livez":             true,
	"GET /readyz":            true,
}

// RegisterAPIDocs publishes the catalogue. The handler walks the router at
// request time rather than at registration time, so routes registered after
// this call — /metrics, the /debug/pprof subtree, the WebSocket upgrade — are
// included too.
func RegisterAPIDocs(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.Get("/api/docs", func(w http.ResponseWriter, _ *http.Request) {
		docs := CatalogueRoutes(r)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":    "success",
			"endpoints": len(docs),
			"data":      docs,
		})
	})
}

// CatalogueRoutes enumerates every route registered on r. Exported so a test
// can assert the catalogue and the router agree — the drift that produced
// SECURE-API-01 was invisible precisely because nothing compared them.
func CatalogueRoutes(r chi.Router) []APIDoc {
	var docs []APIDoc
	mux, ok := r.(*chi.Mux)
	if !ok {
		return docs
	}
	_ = chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		// chi reports the pattern with a trailing slash for subtrees; normalise
		// so the key matches what a caller would request.
		route = strings.TrimSuffix(route, "/*")
		if route == "" {
			route = "/"
		}
		key := method + " " + route
		meta, described := routeDocs[key]
		if !described {
			meta.desc = ""
			meta.auth = !publicRoutes[key]
		}
		docs = append(docs, APIDoc{Method: method, Path: route, Auth: !publicRoutes[key], Desc: meta.desc})
		return nil
	})
	sort.Slice(docs, func(i, j int) bool {
		if docs[i].Path != docs[j].Path {
			return docs[i].Path < docs[j].Path
		}
		return docs[i].Method < docs[j].Method
	})
	return docs
}
