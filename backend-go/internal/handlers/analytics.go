package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	appMW "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

// wafBreaker protects against cascading failures when the WAF service is down.
var wafBreaker = appMW.NewCircuitBreaker(3, 30*time.Second)

// Shared HTTP clients — reused across requests to avoid per-request allocation.
var (
	wafClient   = &http.Client{Timeout: 3 * time.Second}
	probeClient = &http.Client{Timeout: 1 * time.Second}
)

// wafAuth is the credential for the WAF management API: the service token when
// INTERNAL_ALERT_TOKEN is set, otherwise the WAF service credentials, never the
// human admin password as such (see workers.WAFAuth).
func wafAuth(cfg *config.Config) workers.WAFAuth {
	return workers.WAFAuth{Token: cfg.AlertToken, User: cfg.WAFServiceUser, Pass: cfg.WAFServicePass}
}

// wafGet performs a GET request to the WAF management API. The request is
// bound to ctx, so a client disconnect (or the 3s client timeout) cancels the
// upstream call instead of leaking it.
func wafGet(ctx context.Context, cfg *config.Config, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", cfg.WAFURL+path, nil)
	if err != nil {
		return nil, err
	}
	wafAuth(cfg).Apply(req)
	return wafClient.Do(req)
}

// wafPost performs a POST request to the WAF management API.
func wafPost(ctx context.Context, cfg *config.Config, path, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", cfg.WAFURL+path, body)
	if err != nil {
		return nil, err
	}
	wafAuth(cfg).Apply(req)
	req.Header.Set("Content-Type", contentType)
	return wafClient.Do(req)
}

// wafGetBreaker is wafGet behind the circuit breaker: it returns
// appMW.ErrCircuitOpen without a network call when the WAF has been failing, and
// records success/failure so the breaker trips and resets. Every WAF GET
// fan-out goes through this so none can silently drift out of breaker coverage —
// the dashboard /stats poll previously did, blocking each dashboard load for the
// full client timeout whenever the WAF was down.
func wafGetBreaker(ctx context.Context, cfg *config.Config, path string) (*http.Response, error) {
	if err := wafBreaker.Allow(); err != nil {
		return nil, err
	}
	resp, err := wafGet(ctx, cfg, path)
	if err != nil {
		wafBreaker.RecordFailure()
		return nil, err
	}
	wafBreaker.RecordSuccess()
	return resp, nil
}

// wafPostBreaker is wafPost behind the same circuit breaker.
func wafPostBreaker(ctx context.Context, cfg *config.Config, path, contentType string, body io.Reader) (*http.Response, error) {
	if err := wafBreaker.Allow(); err != nil {
		return nil, err
	}
	resp, err := wafPost(ctx, cfg, path, contentType, body)
	if err != nil {
		wafBreaker.RecordFailure()
		return nil, err
	}
	wafBreaker.RecordSuccess()
	return resp, nil
}

type AnalyticsHandlers struct {
	db  *sql.DB
	cfg *config.Config
	// sys supplies update/CVE state. Injected rather than read from another
	// package's globals (SECURE-ARCH-04); nil is valid and omits those fields.
	sys SysInfo

	// domain_blacklist is re-read on every DomainStats request and only changes
	// when the blacklist-refresh worker runs (minutes apart), so a short-TTL
	// snapshot avoids reloading the whole table on each dashboard poll. Snapshots
	// are immutable once published, so callers may read them without the lock.
	// Lifetime request counts, cached: see lifetimeCounts (SECURE-PERF-01).
	countsMu      sync.Mutex
	countsMaxID   int64
	countsTotal   int
	countsBlocked int
	countsFetched time.Time
	// The internal sources the cached counts leave out; every count of one
	// response uses this same list, so today stays within all time.
	countsInternal []string

	// src finds the internal source addresses (the stack's own traffic),
	// which no client count includes.
	src *InternalSources

	blMu      sync.Mutex
	blSet     map[string]struct{}
	blWild    []string
	blFetched time.Time
}

func NewAnalyticsHandlers(db *sql.DB, cfg *config.Config) *AnalyticsHandlers {
	return &AnalyticsHandlers{db: db, cfg: cfg, src: NewInternalSources(db, nil)}
}

// WithSources attaches the internal-source finder the deployment uses; the
// default knows loopback only.
func (h *AnalyticsHandlers) WithSources(s *InternalSources) *AnalyticsHandlers {
	h.src = s
	return h
}

// WithSysInfo attaches the update/CVE provider. Kept separate from the
// constructor so existing call sites and tests need no change.
func (h *AnalyticsHandlers) WithSysInfo(s SysInfo) *AnalyticsHandlers {
	h.sys = s
	return h
}

// lifetimeCountsTTL is short enough that the dashboard stays live and long
// enough that N open tabs cost one pair of scans rather than N.
const lifetimeCountsTTL = 25 * time.Second

// lifetimeBase returns the total and blocked request counts up to row maxID,
// recomputing at most once per lifetimeCountsTTL. See the call site for why
// (SECURE-PERF-01). The three counts and maxID come from one statement, so
// they describe the same rows: a row logged between two separate queries was
// counted by one and not the other.
func (h *AnalyticsHandlers) lifetimeBase() (maxID int64, total, blocked int, internal []string) {
	h.countsMu.Lock()
	defer h.countsMu.Unlock()
	if time.Since(h.countsFetched) < lifetimeCountsTTL {
		return h.countsMaxID, h.countsTotal, h.countsBlocked, h.countsInternal
	}
	internal = h.src.Present()
	// Client requests only (clientRows), from sources that are not internal.
	// The total stays index-only: all rows minus the DNS rows, which
	// idx_proxy_logs_dns counts by itself, minus the internal sources' rows,
	// which idx_proxy_logs_source_ip counts.
	notInt, notArgs := notInternal(internal)
	onlyInt, onlyArgs := onlyInternal(internal)
	var all, dns, internalRows int
	// #nosec G202 -- clientRows and the conditions are constants and placeholders; values are bound.
	_ = h.db.QueryRow(`SELECT
		IFNULL((SELECT MAX(id) FROM proxy_logs), 0),
		(SELECT COUNT(*) FROM proxy_logs),
		(SELECT COUNT(*) FROM proxy_logs WHERE method = 'DNS'),
		(SELECT COUNT(*) FROM proxy_logs WHERE `+onlyInt+` AND `+clientRows+`),
		(SELECT COUNT(*) FROM proxy_logs WHERE blocked = 1 AND `+clientRows+` AND `+notInt+`)`,
		append(onlyArgs, notArgs...)...).Scan(&maxID, &all, &dns, &internalRows, &blocked)
	total = all - dns - internalRows
	h.countsMaxID, h.countsTotal, h.countsBlocked, h.countsInternal, h.countsFetched = maxID, total, blocked, internal, time.Now()
	return maxID, total, blocked, internal
}

// forgetLifetimeCounts drops the cached base, after the logs were cleared.
func (h *AnalyticsHandlers) forgetLifetimeCounts() {
	h.countsMu.Lock()
	h.countsFetched = time.Time{}
	h.countsMu.Unlock()
	h.src.forget()
}

// requestCounts are the dashboard's request counts, all of client rows
// (clientRows) from sources that are not internal.
type requestCounts struct {
	Total, Blocked           int // all time
	Today, TodayBlocked      int // since 00:00 UTC
	Day, DayBlocked, Clients int // the last 24 hours; Clients is distinct source IPs
	LastRequest              string
	// Internal: the internal sources every count leaves out. DayInternal and
	// DayInternalRequests: how many of them sent requests in the last 24
	// hours, and how many requests.
	Internal                         []string
	DayInternal, DayInternalRequests int
}

// requestCounts reads every count the dashboard shows. The all-time counts
// are the cached base plus the rows logged after it (id > maxID, a range on
// the primary key), so they are current without a full scan per poll. The
// cached total used to be compared with a today count read fresh, and the
// dashboard showed today 1,235 next to all time 1,234 for up to 25 seconds.
//
// The rows after the base and the windowed counts are read in one statement,
// one snapshot of the table: no row can be in today and not in all time. Ids
// are AUTOINCREMENT, never reused, so a row is either in the base or after it.
// A delete only makes the cached part too high until the next refresh, which
// keeps today at or below all time.
func (h *AnalyticsHandlers) requestCounts(now time.Time) requestCounts {
	maxID, baseTotal, baseBlocked, internal := h.lifetimeBase()
	todayStart := now.UTC().Truncate(24 * time.Hour).Unix()
	dayStart := now.Add(-24 * time.Hour).Unix()
	c := requestCounts{Internal: internal}
	var newTotal, newBlocked int
	ext, extArgs := notInternal(internal)
	in, inArgs := onlyInternal(internal)
	args := []any{maxID}
	args = append(args, extArgs...)
	args = append(args, todayStart)
	args = append(args, extArgs...)
	args = append(args, dayStart)
	args = append(args, extArgs...)
	args = append(args, dayStart)
	args = append(args, inArgs...)
	// #nosec G202 -- clientRows and the conditions are constants and placeholders; values are bound.
	_ = h.db.QueryRow(`SELECT n.total, n.blocked, t.total, t.blocked, d.total, d.blocked, d.clients, d.last, i.sources, i.total
		FROM (SELECT COUNT(*) AS total, IFNULL(SUM(blocked), 0) AS blocked
		        FROM proxy_logs WHERE id > ? AND `+clientRows+` AND `+ext+`) AS n,
		     (SELECT COUNT(*) AS total, IFNULL(SUM(blocked), 0) AS blocked
		        FROM proxy_logs WHERE unix_timestamp >= ? AND `+clientRows+` AND `+ext+`) AS t,
		     (SELECT COUNT(*) AS total, IFNULL(SUM(blocked), 0) AS blocked,
		             COUNT(DISTINCT CASE WHEN source_ip != '' THEN source_ip END) AS clients,
		             IFNULL(MAX(timestamp), '') AS last
		        FROM proxy_logs WHERE unix_timestamp >= ? AND `+clientRows+` AND `+ext+`) AS d,
		     (SELECT COUNT(DISTINCT source_ip) AS sources, COUNT(*) AS total
		        FROM proxy_logs WHERE unix_timestamp >= ? AND `+clientRows+` AND `+in+`) AS i`,
		args...,
	).Scan(&newTotal, &newBlocked, &c.Today, &c.TodayBlocked, &c.Day, &c.DayBlocked, &c.Clients, &c.LastRequest,
		&c.DayInternal, &c.DayInternalRequests)
	c.Total, c.Blocked = baseTotal+newTotal, baseBlocked+newBlocked
	return c
}

const domainBlacklistTTL = 30 * time.Second

// domainBlacklist returns a cached snapshot of the domain blacklist (exact-match
// set + wildcard suffixes), refreshing from the DB at most once per TTL.
func (h *AnalyticsHandlers) domainBlacklist() (map[string]struct{}, []string) {
	h.blMu.Lock()
	defer h.blMu.Unlock()
	if h.blSet != nil && time.Since(h.blFetched) < domainBlacklistTTL {
		return h.blSet, h.blWild
	}
	set := map[string]struct{}{}
	var wild []string
	rows, _ := h.db.Query("SELECT domain FROM domain_blacklist")
	if rows != nil {
		for rows.Next() {
			var d string
			rows.Scan(&d) //nolint:errcheck
			set[d] = struct{}{}
			if strings.HasPrefix(d, "*.") {
				wild = append(wild, d[2:])
			}
		}
		rows.Close()
	}
	h.blSet, h.blWild, h.blFetched = set, wild, time.Now()
	return set, wild
}

func (h *AnalyticsHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	// etag adds conditional-GET revalidation to read-heavy analytics payloads so
	// repeated dashboard polls return 304 when the data is unchanged.
	etag := appMW.ETag
	r.With(authMW).Get("/api/status", h.Status)
	r.With(authMW, etag).Get("/api/traffic/statistics", h.TrafficStats)
	r.With(authMW, etag).Get("/api/clients/statistics", h.ClientStats)
	r.With(authMW).Get("/api/clients/{ip}/details", h.ClientDetails)
	r.With(authMW, etag).Get("/api/domains/statistics", h.DomainStats)
	r.With(authMW).Get("/api/cache/statistics", h.CacheStats)
	r.With(authMW).Get("/api/waf/stats", h.WAFStats)
	r.With(authMW).Get("/api/waf/categories", h.WAFCategories)
	r.With(authMW).Post("/api/waf/categories/toggle", h.WAFCategoryToggle)
	r.With(authMW).Post("/api/counters/reset", h.ResetCounters)
	r.With(authMW, etag).Get("/api/dashboard/summary", h.DashboardSummary)
	r.With(authMW, etag).Get("/api/analytics/shadow-it", h.ShadowIT)
	r.With(authMW, etag).Get("/api/analytics/user-agents", h.UserAgents)
	r.With(authMW, etag).Get("/api/analytics/file-extensions", h.FileExtensions)
	r.With(authMW, etag).Get("/api/analytics/top-domains", h.TopDomains)
	r.With(authMW, etag).Get("/api/audit-log", h.AuditLog)
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
	h.db.QueryRow("SELECT COUNT(*) FROM proxy_logs WHERE timestamp >= ? AND timestamp < date(?, '+1 day') AND "+clientRows, todayStr, todayStr).Scan(&todayCount) //nolint:errcheck

	// Read the configured proxy port rather than hard-coding 3128.
	proxyPort := "3128"
	h.db.QueryRow("SELECT setting_value FROM settings WHERE setting_name = 'proxy_port'").Scan(&proxyPort) //nolint:errcheck

	// The Squid version, its known CVEs and the update check live here, behind
	// authMW, rather than on the unauthenticated /api/health where they
	// fingerprinted the deployment for any pre-auth caller (SECURE-AUTH-04).
	out := map[string]any{
		"proxy_status":   proxyStatus,
		"proxy_host":     h.cfg.ProxyHost,
		"proxy_port":     proxyPort,
		"timestamp":      time.Now().Format(time.RFC3339),
		"version":        config.AppVersion,
		"requests_count": todayCount,
		"memory_usage":   "N/A",
		"cpu_usage":      "N/A",
		"uptime":         "N/A",
		"commit":         config.GitCommit,
	}
	if h.sys != nil {
		if upd := h.sys.UpdateInfo(); upd.Available {
			out["update_available"] = upd.Latest
			out["update_url"] = upd.URL
		}
		if cve := h.sys.CVEInfo(); cve.Version != "" {
			out["squid_version"] = cve.Version
			out["squid_cves"] = len(cve.CVEs)
		}
	}
	writeOK(w, out)
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
		// Bucket into 5-minute slots (rounded down via epoch) so the keys line up
		// with the 5-minute label grid below. A per-minute %H:%M key never matched
		// the 5-min-stepped labels, dropping ~all points.
		interval = `strftime('%Y-%m-%d %H:%M', datetime((unix_timestamp / 300) * 300, 'unixepoch'))`
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
		       SUM(blocked) AS blocked
		FROM proxy_logs WHERE unix_timestamp >= ? AND `+clientRows+` GROUP BY bucket`,
		sinceUnix(parseDuration(startDuration)),
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

	// Build labels array from now back. Use UTC to match the UTC timestamps that
	// the log tailer writes (and that strftime buckets above).
	var labels []string
	var inbound, outbound, blocked []int
	now := time.Now().UTC()
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
	// Align the hour grid to 5-minute boundaries (:00,:05,…) so labels match the
	// 5-minute SQL buckets.
	if period == "hour" {
		startT = startT.Truncate(step)
	}
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
	if v, err := strconv.Atoi(parts[0]); err == nil {
		n = v
	}
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

// analyticsWindow is the rolling window for the "top N over recent activity"
// panels (clients, domains, threat categories, SaaS). One constant keeps the
// panels from drifting apart.
const analyticsWindow = 7 * 24 * time.Hour

// destinationKey is the SQL expression a top list groups destinations by: the
// host. Squid logs a CONNECT as "host:443", a plain HTTP request as its full
// URL ("http://host/login") and the DNS sinkhole logs the same site as
// "host", so grouping on the raw column split one destination into a row per
// form and per path, each with part of the count.
var destinationKey = hostKey("destination")

// hostKey returns the SQL expression that reduces the destination in column
// col to its host, in three steps:
//
//   - after the scheme: "http://host/login" -> "host/login" (no "://", as
//     in "host:443", leaves it as it is);
//   - before the path: "host/login" -> "host";
//   - without a default port: a trailing :443 or :80 is dropped; any other
//     port stays, because it is another service. LIKE ':443' needs the colon,
//     so "host:8443" keeps its port.
//
// col is a column name written by the caller, never a value.
func hostKey(col string) string {
	scheme := "instr(" + col + ", '://')"
	// substr from 1 when there is no scheme, from just after "://" otherwise.
	rest := "substr(" + col + ", 1 + (" + scheme + " + 2) * (" + scheme + " > 0))"
	// Appending "/" makes instr find one in a bare host too.
	hostPort := "substr(" + rest + ", 1, instr(" + rest + " || '/', '/') - 1)"
	return `CASE
	WHEN ` + hostPort + ` LIKE '%:443' THEN substr(` + hostPort + `, 1, length(` + hostPort + `) - 4)
	WHEN ` + hostPort + ` LIKE '%:80' THEN substr(` + hostPort + `, 1, length(` + hostPort + `) - 3)
	ELSE ` + hostPort + ` END`
}

// sinceUnix returns the Unix-epoch lower bound for a rolling window of length d.
// Binding this and filtering `unix_timestamp >= ?` lets the query range-scan
// idx_proxy_logs_unix_ts instead of doing per-row TEXT-date arithmetic with
// datetime('now', ...), which never used the index.
func sinceUnix(d time.Duration) int64 { return time.Now().Add(-d).Unix() }

// clientRows restricts a proxy_logs query to client requests, and every
// statistic uses it. The rows it leaves out are the dnsmasq sinkhole answers
// (method DNS): lookups the proxy container made on behalf of a client whose
// request Squid logs itself (workers.parseDNSLine). Counted, they made the
// proxy a client with only blocked requests and counted a client's one
// request up to three times (Squid's line, the A answer and the AAAA answer).
// IFNULL keeps rows with no method, which only tests and very old rows have.
const clientRows = "IFNULL(method, '') != 'DNS'"

// blockedByReason counts the blocked client requests matching where (a
// condition on proxy_logs, with its arguments) by block_reason, largest
// first. Rows logged before reasons were recorded count as "unclassified";
// no reason is assigned to them after the fact.
func (h *AnalyticsHandlers) blockedByReason(where string, args ...any) []map[string]any {
	return blockedByReason(h.db, where, args...)
}

func blockedByReason(db *sql.DB, where string, args ...any) []map[string]any {
	out := []map[string]any{}
	// #nosec G202 -- where is a constant at every call site; values are bound.
	rows, err := db.Query(`SELECT block_reason, COUNT(*) AS cnt FROM proxy_logs
		WHERE blocked = 1 AND `+clientRows+` AND `+where+`
		GROUP BY block_reason ORDER BY cnt DESC, block_reason`, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var reason string
		var cnt int
		if rows.Scan(&reason, &cnt) != nil {
			continue
		}
		out = append(out, map[string]any{"reason": reason, "label": workers.ReasonLabel(reason), "count": cnt})
	}
	return out
}

// clientsLimit is how many clients, other than internal sources, the client
// list returns: the ones with the most requests.
const clientsLimit = 50

// ClientStats lists the sources of the last 7 days: the clientsLimit clients
// with the most requests, then every internal source (the stack's own
// traffic), each marked internal with what it is (kind) where that is known.
// meta.total counts the clients other than internal sources, meta.internal
// the internal ones. blocked counts the client rows the backend recorded as
// blocked, whatever the reason, "unclassified" rows from before reasons were
// recorded included.
func (h *AnalyticsHandlers) ClientStats(w http.ResponseWriter, r *http.Request) {
	since := sinceUnix(analyticsWindow)
	internal := h.src.Present()
	ext, extArgs := notInternal(internal)
	in, inArgs := onlyInternal(internal)
	clients := []map[string]any{}
	read := func(cond string, args []any, limit int) error {
		// #nosec G202 -- clientRows and cond are constants and placeholders; values are bound.
		rows, err := h.db.Query(`
			SELECT source_ip, COUNT(*) AS requests,
			       SUM(blocked) AS blocked,
			       MAX(timestamp) AS last_seen
			FROM proxy_logs
			WHERE source_ip IS NOT NULL AND source_ip != '' AND unix_timestamp >= ? AND `+clientRows+` AND `+cond+`
			GROUP BY source_ip ORDER BY requests DESC, source_ip LIMIT ?`, append(append([]any{since}, args...), limit)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ip string
			var cnt, blocked int
			var lastSeen sql.NullString
			rows.Scan(&ip, &cnt, &blocked, &lastSeen) //nolint:errcheck
			isInternal, kind := h.src.Classify(ip)
			clients = append(clients, map[string]any{
				"ip_address": ip, "requests": cnt, "blocked": blocked,
				"last_seen": lastSeen.String, "status": "Active",
				"internal": isInternal, "kind": kind,
			})
		}
		return rows.Err()
	}
	if err := read(ext, extArgs, clientsLimit); err != nil {
		writeInternalError(w, "client_stats", err)
		return
	}
	if err := read(in, inArgs, len(internal)+1); err != nil {
		writeInternalError(w, "client_stats", err)
		return
	}
	var total, internalTotal int
	// #nosec G202 -- clientRows and the conditions are constants and placeholders; values are bound.
	h.db.QueryRow(`SELECT
		(SELECT COUNT(DISTINCT source_ip) FROM proxy_logs WHERE source_ip IS NOT NULL AND source_ip != '' AND unix_timestamp >= ? AND `+clientRows+` AND `+ext+`),
		(SELECT COUNT(DISTINCT source_ip) FROM proxy_logs WHERE unix_timestamp >= ? AND `+clientRows+` AND `+in+`)`,
		append(append(append([]any{since}, extArgs...), since), inArgs...)...).Scan(&total, &internalTotal) //nolint:errcheck
	// The collection goes under data like every other list, with its count in
	// meta — not nested under data.clients with the count beside it, which was
	// the third of the three shapes (SECURE-API-02).
	writeList(w, clients, ListMeta{Total: total, Limit: clientsLimit, Offset: 0, Internal: &internalTotal})
}

// ClientDetails returns a per-client drill-down for a single source IP:
// totals, top destinations (with how many were blocked), and the most recent
// requests. The IP is bound as a query parameter, so it is not an injection
// vector; isValidCIDR rejects obviously malformed input early.
func (h *AnalyticsHandlers) ClientDetails(w http.ResponseWriter, r *http.Request) {
	ip := chi.URLParam(r, "ip")
	if !isValidCIDR(ip) {
		writeError(w, http.StatusBadRequest, "invalid IP address")
		return
	}
	const blockedCase = `SUM(blocked)`

	var total, blocked int
	var firstSeen, lastSeen sql.NullString
	// A no-rows or scan error leaves the zero values, which is the correct
	// answer for a client with no logged requests.
	_ = h.db.QueryRow(
		`SELECT COUNT(*), IFNULL(`+blockedCase+`, 0), MIN(timestamp), MAX(timestamp) FROM proxy_logs WHERE source_ip = ? AND `+clientRows,
		ip,
	).Scan(&total, &blocked, &firstSeen, &lastSeen)

	topDomains := []map[string]any{}
	// #nosec G202 -- destinationKey is built once from a constant column name by hostKey; values are bound.
	if dr, err := h.db.Query(
		`SELECT `+destinationKey+` AS dest, COUNT(*) AS c, `+blockedCase+` AS b
		 FROM proxy_logs WHERE source_ip = ? AND destination IS NOT NULL AND destination != '' AND `+clientRows+`
		 GROUP BY dest ORDER BY c DESC LIMIT 10`, ip); err == nil {
		for dr.Next() {
			var d string
			var c, b int
			dr.Scan(&d, &c, &b) //nolint:errcheck
			topDomains = append(topDomains, map[string]any{"destination": d, "requests": c, "blocked": b})
		}
		dr.Close()
	}

	recent := []map[string]any{}
	if rr, err := h.db.Query(
		`SELECT timestamp, method, destination, status, bytes, block_reason
		 FROM proxy_logs WHERE source_ip = ? AND `+clientRows+` ORDER BY id DESC LIMIT 20`, ip); err == nil {
		for rr.Next() {
			var ts, method, dest, status, reason string
			var nbytes int64
			rr.Scan(&ts, &method, &dest, &status, &nbytes, &reason) //nolint:errcheck
			recent = append(recent, map[string]any{
				"timestamp": ts, "method": method, "destination": dest, "status": status, "bytes": nbytes,
				"reason": reason,
			})
		}
		rr.Close()
	}

	isInternal, kind := h.src.Classify(ip)
	writeOK(w, map[string]any{
		"ip_address":     ip,
		"internal":       isInternal,
		"kind":           kind,
		"total_requests": total,
		"blocked":        blocked,
		"first_seen":     firstSeen.String,
		"last_seen":      lastSeen.String,
		"top_domains":    topDomains,
		"recent":         recent,
		// The client's blocked requests by the rule that blocked them.
		"blocked_by_reason": h.blockedByReason(`source_ip = ?`, ip),
	})
}

func (h *AnalyticsHandlers) DomainStats(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`
		SELECT destination, COUNT(*) AS requests,
		       SUM(blocked) AS blocked_requests
		FROM proxy_logs WHERE destination IS NOT NULL AND destination != '' AND unix_timestamp >= ? AND `+clientRows+`
		GROUP BY destination ORDER BY requests DESC LIMIT 50`, sinceUnix(analyticsWindow))
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

	blSet, wildcards := h.domainBlacklist()

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
	statsFile := filepath.Join(h.cfg.ConfigDir, "cache_stats.txt")
	content, err := os.ReadFile(statsFile) // #nosec G304 — statsFile is a fixed internal config path
	if err != nil {
		log.Debug().Err(err).Msg("failed to read shared cache_stats.txt file, returning zeros")
		writeOK(w, map[string]any{
			"hit_rate": 0, "byte_hit_rate": 0, "cache_size": "N/A",
			"max_cache_size": "N/A", "objects_cached": 0, "hits": 0,
			"misses": 0, "requests": 0, "simulated": true,
		})
		return
	}
	writeOK(w, parseSquidInfo(string(content)))
}

// parseSquidInfo extracts cache metrics from squidclient mgr:info output.
func parseSquidInfo(raw string) map[string]any {
	result := map[string]any{
		"hit_rate": 0.0, "byte_hit_rate": 0.0, "cache_size": "N/A",
		"max_cache_size": "N/A", "objects_cached": 0, "hits": 0,
		"misses": 0, "requests": 0, "simulated": false,
	}
	for _, line := range strings.Split(raw, "\n") {
		parseSquidInfoLine(result, strings.TrimSpace(line))
	}
	// Compute misses from requests - hits. hit_ratio is deliberately NOT
	// emitted: it was a SECOND cache hit rate, computed over the lifetime
	// counters while hit_rate comes from Squid's 5-minute window. They measure
	// different things and diverge, and the two UI surfaces read different ones
	// — the Dashboard preferred hit_ratio, the Settings service panel used
	// hit_rate — so the same deployment showed two different numbers under the
	// same label. hit_rate is the single definition (SECURE-DOM-03).
	if reqs, ok := result["requests"].(int); ok {
		if hits, ok := result["hits"].(int); ok {
			result["misses"] = reqs - hits
		}
	}
	return result
}

// parseSquidInfoLine folds one (trimmed) line of the cache manager's info
// report into result.
func parseSquidInfoLine(result map[string]any, line string) {
	switch {
	case strings.HasPrefix(line, "Request Hit Ratios:"):
		setFiveMinuteRatio(result, "hit_rate", line)
	case strings.HasPrefix(line, "Byte Hit Ratios:"):
		setFiveMinuteRatio(result, "byte_hit_rate", line)
	case strings.HasPrefix(line, "Storage Swap size:"):
		// "Storage Swap size:	1234 KB"
		result["cache_size"] = strings.TrimSpace(strings.TrimPrefix(line, "Storage Swap size:"))
	case strings.HasPrefix(line, "Maximum Swap Size:"):
		result["max_cache_size"] = strings.TrimSpace(strings.TrimPrefix(line, "Maximum Swap Size:"))
	case strings.HasPrefix(line, "StoreEntries"):
		// "StoreEntries                : 1234"
		setIntAfter(result, "objects_cached", line, ":")
	case strings.Contains(line, "client_http.requests"):
		setIntAfter(result, "requests", line, "=")
	case strings.Contains(line, "client_http.hits"):
		setIntAfter(result, "hits", line, "=")
	}
}

// setFiveMinuteRatio stores the 5-minute window of a "Hit Ratios" line as a
// fraction: "Request Hit Ratios:     5min: 42.3%, 60min: 38.1%" -> 0.423.
func setFiveMinuteRatio(result map[string]any, key, line string) {
	parts := strings.SplitN(line, "5min:", 2)
	if len(parts) != 2 {
		return
	}
	val := strings.TrimSpace(strings.SplitN(parts[1], "%", 2)[0])
	if f, err := strconv.ParseFloat(val, 64); err == nil {
		result[key] = f / 100
	}
}

// setIntAfter stores the integer after the first sep in line, if there is one.
func setIntAfter(result map[string]any, key, line, sep string) {
	parts := strings.SplitN(line, sep, 2)
	if len(parts) != 2 {
		return
	}
	if n, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
		result[key] = n
	}
}

func (h *AnalyticsHandlers) WAFStats(w http.ResponseWriter, r *http.Request) {
	resp, err := wafGetBreaker(r.Context(), h.cfg, "/stats")
	if err != nil {
		if errors.Is(err, appMW.ErrCircuitOpen) {
			writeError(w, http.StatusServiceUnavailable, "WAF service circuit open — retrying soon")
		} else {
			writeError(w, http.StatusBadGateway, "WAF service unreachable")
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, "WAF stats returned "+resp.Status)
		return
	}
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
	h.forgetLifetimeCounts()

	// The log delete above is unconditional; the WAF reset is best-effort and
	// behind the breaker, so a down/circuit-open WAF can't gate the DB clear.
	wafReset := false
	if resp, err := wafPostBreaker(r.Context(), h.cfg, "/reset", "application/json", nil); err == nil {
		resp.Body.Close()
		wafReset = resp.StatusCode == 200
	}
	writeOK(w, map[string]any{"logs_cleared": deleted, "waf_reset": wafReset})
}

func (h *AnalyticsHandlers) DashboardSummary(w http.ResponseWriter, r *http.Request) {
	result := map[string]any{}

	// The lifetime counts come from a short-TTL cache, not from two COUNT(*)
	// scans per poll. SQLite keeps no cached row count, so an unqualified
	// COUNT(*) walks an index end to end — over proxy_logs, the one table whose
	// size tracks traffic rather than configuration — and the Dashboard and
	// Threat Intel pages both poll this endpoint every 30 seconds, per open tab,
	// on a container limited to 0.25 CPU. The ETag on this route does not help:
	// it hashes the response body, so every query has already run by the time
	// the 304 is decided (SECURE-PERF-01).
	c := h.requestCounts(time.Now())

	var ipBLCount, domainBLCount int

	result["total_requests"] = c.Total
	result["blocked_requests"] = c.Blocked
	result["today_requests"] = c.Today
	result["today_blocked"] = c.TodayBlocked
	// The last 24 hours, the window of top_blocked, top_clients and
	// blocked_by_reason_24h. last_24h_clients counts the distinct source IPs,
	// which top_clients (at most 10) cannot.
	result["last_24h_requests"] = c.Day
	result["last_24h_blocked"] = c.DayBlocked
	result["last_24h_clients"] = c.Clients
	// Every count here leaves out the internal sources: the stack's own
	// traffic (sources.Classifier). These say how many were left out of the
	// last 24 hours, and how many requests they sent.
	result["last_24h_internal_sources"] = c.DayInternal
	result["last_24h_internal_requests"] = c.DayInternalRequests
	ext, extArgs := notInternal(c.Internal)
	day := sinceUnix(24 * time.Hour)
	if c.LastRequest != "" {
		result["last_request_at"] = c.LastRequest
	} else {
		result["last_request_at"] = nil
	}

	result["top_blocked"] = h.topBlocked(day, c.Internal)

	h.db.QueryRow("SELECT COUNT(*) FROM ip_blacklist").Scan(&ipBLCount)         //nolint:errcheck
	h.db.QueryRow("SELECT COUNT(*) FROM domain_blacklist").Scan(&domainBLCount) //nolint:errcheck
	// Note: these two are on different tables so cannot be combined into the proxy_logs query above.
	result["ip_blacklist_count"] = ipBLCount
	result["domain_blacklist_count"] = domainBLCount
	// Whether Squid holds the domain blacklist itself, as the proxy recorded
	// it; null when the proxy has not written its record.
	if s := readDomainACLStatus(h.cfg.ConfigDir); s != nil {
		result["squid_domain_acl"] = s
	} else {
		result["squid_domain_acl"] = nil
	}

	// Top clients (last 24h)
	var topClients []map[string]any
	// #nosec G202 -- clientRows and ext are constants and placeholders; values are bound.
	cRows, _ := h.db.Query(`SELECT source_ip, COUNT(*) AS cnt FROM proxy_logs WHERE unix_timestamp >= ? AND source_ip IS NOT NULL AND source_ip != '' AND `+clientRows+` AND `+ext+` GROUP BY source_ip ORDER BY cnt DESC LIMIT 10`, append([]any{day}, extArgs...)...)
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

	// Blocked requests by the rule that blocked them (last 7 days). This used
	// to be guessed from strings: any status with 403 was "WAF Block" (Squid's
	// own denials log 403 too) and any denied destination with ':' was "Direct
	// IP" (every denied CONNECT host:443). The reason is now recorded per row.
	// threat_categories keeps its shape for the current UI, with the reason's
	// label as the category.
	byReason := h.blockedByReason(`unix_timestamp >= ? AND `+ext, append([]any{sinceUnix(analyticsWindow)}, extArgs...)...)
	threatCats := make([]map[string]any, 0, len(byReason))
	for _, r := range byReason {
		threatCats = append(threatCats, map[string]any{"category": r["label"], "count": r["count"]})
	}
	result["blocked_by_reason"] = byReason
	result["threat_categories"] = threatCats
	// The same, over the last 24 hours.
	result["blocked_by_reason_24h"] = h.blockedByReason(`unix_timestamp >= ? AND `+ext, append([]any{day}, extArgs...)...)

	// Recent blocks: the last 10 of the same 24 hours the counts above cover,
	// so the page never lists a block its "blocked by rule" does not count.
	var recentBlocks []map[string]any
	// #nosec G202 -- destinationKey and clientRows are constant expressions.
	rRows, _ := h.db.Query(`SELECT timestamp, source_ip, method, destination, `+destinationKey+`, status, block_reason
		FROM proxy_logs WHERE blocked = 1 AND unix_timestamp >= ? AND `+clientRows+` AND `+ext+` ORDER BY id DESC LIMIT 10`, append([]any{day}, extArgs...)...)
	if rRows != nil {
		for rRows.Next() {
			var ts, srcIP, method, dest, host, status, reason sql.NullString
			rRows.Scan(&ts, &srcIP, &method, &dest, &host, &status, &reason) //nolint:errcheck
			recentBlocks = append(recentBlocks, map[string]any{
				"timestamp": ts.String, "source_ip": srcIP.String, "method": method.String,
				"destination": dest.String, "host": host.String, "status": status.String,
				"reason": reason.String, "reason_label": workers.ReasonLabel(reason.String),
			})
		}
		rRows.Close()
	}
	if recentBlocks == nil {
		recentBlocks = []map[string]any{}
	}
	result["recent_blocks"] = recentBlocks

	// WAF stats — behind the circuit breaker so a down or circuit-open WAF
	// degrades only this sub-field (and counts toward tripping the breaker)
	// instead of blocking every dashboard load for the full client timeout. The
	// rest of the dashboard is DB-sourced and must still render.
	//
	// waf_status says WHY waf is null. It used to be null with no reason and
	// no log line, and the UI hid its WAF cards, so a WAF that refused every
	// management call looked like a deployment without a WAF.
	result["waf"] = nil
	result["waf_status"] = "unreachable"
	if resp, err := wafGetBreaker(r.Context(), h.cfg, "/stats"); err == nil {
		switch resp.StatusCode {
		case http.StatusOK:
			var wafData any
			if json.NewDecoder(resp.Body).Decode(&wafData) == nil {
				result["waf"] = wafData
				result["waf_status"] = "ok"
			} else {
				result["waf_status"] = "error"
			}
		case http.StatusUnauthorized, http.StatusForbidden:
			result["waf_status"] = "auth_failed"
			warnWAFStatus("WAF management API refused the backend's credential: WAF statistics and toggles are unavailable. "+
				"Set INTERNAL_ALERT_TOKEN to the same value on the waf and backend services.", resp.StatusCode)
		default:
			result["waf_status"] = "error"
			warnWAFStatus("WAF management API returned an unexpected status", resp.StatusCode)
		}
		resp.Body.Close()
	}
	writeOK(w, result)
}

// topBlocked lists the 10 hosts with the most blocked client requests since
// the Unix time since, from sources other than internal, each with its count
// and the rules that blocked it (largest first). A host can be blocked by
// more than one rule: the DNS sinkhole and Squid's own domain ACL both block
// a blacklisted name.
func (h *AnalyticsHandlers) topBlocked(since int64, internal []string) []map[string]any {
	out := []map[string]any{}
	ext, extArgs := notInternal(internal)
	// #nosec G202 -- destinationKey, clientRows and ext are constants and placeholders; values are bound.
	rows, err := h.db.Query(`WITH b AS (
			SELECT `+destinationKey+` AS dest, block_reason AS reason FROM proxy_logs
			WHERE blocked = 1 AND unix_timestamp >= ? AND `+clientRows+` AND `+ext+`),
		top AS (SELECT dest, COUNT(*) AS cnt FROM b GROUP BY dest ORDER BY cnt DESC, dest LIMIT 10)
		SELECT top.dest, top.cnt, b.reason, COUNT(*) AS n FROM top JOIN b ON b.dest = top.dest
		GROUP BY top.dest, b.reason ORDER BY top.cnt DESC, top.dest, n DESC, b.reason`, append([]any{since}, extArgs...)...)
	if err != nil {
		return out
	}
	defer rows.Close()
	var cur map[string]any
	for rows.Next() {
		var dest, reason string
		var cnt, n int
		if rows.Scan(&dest, &cnt, &reason, &n) != nil {
			continue
		}
		if cur == nil || cur["dest"] != dest {
			cur = map[string]any{"dest": dest, "count": cnt, "reasons": []map[string]any{}}
			out = append(out, cur)
		}
		cur["reasons"] = append(cur["reasons"].([]map[string]any),
			map[string]any{"reason": reason, "label": workers.ReasonLabel(reason), "count": n})
	}
	return out
}

// warnWAFStatus logs a WAF management failure at most once per ten minutes:
// the dashboard polls every 30 s per open tab.
var lastWAFStatusWarn atomic.Int64

func warnWAFStatus(msg string, status int) {
	now := time.Now().Unix()
	last := lastWAFStatusWarn.Load()
	if now-last < 600 || !lastWAFStatusWarn.CompareAndSwap(last, now) {
		return
	}
	log.Warn().Int("status", status).Msg(msg)
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
		AND unix_timestamp >= ? AND `+clientRows+`
		GROUP BY destination ORDER BY cnt DESC LIMIT 500`, sinceUnix(analyticsWindow))
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
	since := sinceUnix(analyticsWindow)
	rows, err := h.db.Query(`
		SELECT method, COUNT(*) AS cnt FROM proxy_logs
		WHERE method IS NOT NULL AND method != '' AND method != '-'
		AND unix_timestamp >= ? AND `+clientRows+`
		GROUP BY method ORDER BY cnt DESC LIMIT 50`, since)
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

	stRows, err := h.db.Query(`
		SELECT
			CASE
				WHEN destination LIKE '%googleapis.com%' OR destination LIKE '%google.com%' THEN 'Google Services'
				WHEN destination LIKE '%microsoft.com%' OR destination LIKE '%office.com%' OR destination LIKE '%live.com%' THEN 'Microsoft'
				WHEN destination LIKE '%apple.com%' OR destination LIKE '%icloud.com%' THEN 'Apple'
				WHEN destination LIKE '%github.com%' OR destination LIKE '%gitlab%' THEN 'Dev Tools'
				WHEN destination LIKE '%docker%' OR destination LIKE '%registry%' THEN 'Containers'
				WHEN destination LIKE '%npm%' OR destination LIKE '%pypi%' OR destination LIKE '%maven%' THEN 'Package Managers'
				WHEN destination LIKE '%cdn%' OR destination LIKE '%cloudflare%' OR destination LIKE '%akamai%' THEN 'CDN'
				WHEN destination LIKE '%update%' OR destination LIKE '%patch%' THEN 'Updates'
				ELSE 'Other'
			END as service_type,
			COUNT(*) as cnt
		FROM proxy_logs
		WHERE unix_timestamp >= ? AND destination IS NOT NULL AND `+clientRows+`
		GROUP BY service_type ORDER BY cnt DESC`, since)
	var serviceTypes []map[string]any
	if err == nil {
		defer stRows.Close()
		for stRows.Next() {
			var name string
			var cnt int
			stRows.Scan(&name, &cnt) //nolint:errcheck
			serviceTypes = append(serviceTypes, map[string]any{"name": name, "count": cnt})
		}
	}
	if serviceTypes == nil {
		serviceTypes = []map[string]any{}
	}

	writeOK(w, map[string]any{
		"methods":       methods,
		"service_types": serviceTypes,
	})
}

var extRe = regexp.MustCompile(`\.([a-zA-Z0-9]{1,10})(?:\?|$|#)`)

func (h *AnalyticsHandlers) FileExtensions(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`SELECT destination FROM proxy_logs WHERE destination IS NOT NULL AND destination != '' AND unix_timestamp >= ? AND `+clientRows+` LIMIT 10000`, sinceUnix(analyticsWindow))
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

	type extItem struct {
		Ext   string `json:"ext"`
		Count int    `json:"count"`
	}
	var exts []extItem
	for e, c := range extCounts {
		exts = append(exts, extItem{"." + e, c})
	}
	sort.Slice(exts, func(i, j int) bool {
		return exts[i].Count > exts[j].Count
	})
	if len(exts) > 30 {
		exts = exts[:30]
	}

	categoriesMap := map[string][]string{
		"Web":         {"html", "htm", "css", "js", "jsx", "ts", "tsx", "woff", "woff2", "ttf", "svg", "ico", "webmanifest"},
		"Images":      {"png", "jpg", "jpeg", "gif", "webp", "bmp", "avif", "tiff"},
		"Documents":   {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "txt", "rtf"},
		"Archives":    {"zip", "tar", "gz", "bz2", "7z", "rar", "xz"},
		"Media":       {"mp4", "mp3", "avi", "mkv", "wav", "ogg", "flac", "m4a"},
		"Code":        {"py", "go", "rs", "java", "c", "cpp", "rb", "php", "sh", "yaml", "yml", "json", "xml", "toml"},
		"Executables": {"exe", "msi", "dmg", "deb", "rpm", "apk", "bin"},
		"Data":        {"sql", "db", "sqlite", "bak", "dump"},
	}

	catCounts := map[string]int{}
	for ext, count := range extCounts {
		category := "Other"
		for catName, extsList := range categoriesMap {
			found := false
			for _, x := range extsList {
				if x == ext {
					found = true
					break
				}
			}
			if found {
				category = catName
				break
			}
		}
		catCounts[category] += count
	}

	type catItem struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
	}
	var categories []catItem
	for cat, count := range catCounts {
		categories = append(categories, catItem{cat, count})
	}
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Count > categories[j].Count
	})

	writeOK(w, map[string]any{
		"extensions": exts,
		"categories": categories,
	})
}

func (h *AnalyticsHandlers) TopDomains(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(`
		SELECT destination, COUNT(*) AS cnt FROM proxy_logs
		WHERE destination IS NOT NULL AND destination != ''
		AND unix_timestamp >= ? AND `+clientRows+`
		GROUP BY destination ORDER BY cnt DESC LIMIT 200`, sinceUnix(analyticsWindow))
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
	total, err := countRows(h.db, "SELECT COUNT(*) FROM audit_log")
	if err != nil {
		writeInternalError(w, "audit_log_count", err)
		return
	}
	rows, err := h.db.Query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		writeInternalError(w, "audit_log", err)
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
	writeList(w, entries, ListMeta{Total: total, Limit: limit, Offset: offset})
}

// WAFCategories proxies GET /categories from the WAF container.
func (h *AnalyticsHandlers) WAFCategories(w http.ResponseWriter, r *http.Request) {
	resp, err := wafGetBreaker(r.Context(), h.cfg, "/categories")
	if err != nil {
		if errors.Is(err, appMW.ErrCircuitOpen) {
			writeError(w, http.StatusServiceUnavailable, "WAF circuit open")
		} else {
			writeError(w, http.StatusBadGateway, "WAF unreachable")
		}
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// WAFCategoryToggle proxies POST /categories/toggle to WAF.
func (h *AnalyticsHandlers) WAFCategoryToggle(w http.ResponseWriter, r *http.Request) {
	resp, err := wafPostBreaker(r.Context(), h.cfg, "/categories/toggle", "application/json", r.Body)
	if err != nil {
		if errors.Is(err, appMW.ErrCircuitOpen) {
			writeError(w, http.StatusServiceUnavailable, "WAF circuit open")
		} else {
			writeError(w, http.StatusBadGateway, "WAF unreachable")
		}
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
		"SELECT destination FROM proxy_logs WHERE unix_timestamp >= ? AND destination IS NOT NULL AND destination != '' AND "+clientRows+" LIMIT 10000",
		sinceUnix(time.Duration(req.Hours)*time.Hour),
	)
	if err != nil {
		writeInternalError(w, "waf_test_rule", err)
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
