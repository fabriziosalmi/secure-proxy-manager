// Package metrics exposes Prometheus instrumentation for the backend: RED
// metrics for the HTTP surface, database connection-pool gauges, build info, and
// per-worker heartbeats. It registers everything on the default registry (which
// already carries the Go runtime and process collectors), so /metrics also
// surfaces go_* and process_* without extra wiring.
package metrics

import (
	"database/sql"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

var (
	// HTTPRequests counts handled requests by method, matched route pattern and status.
	HTTPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "spm_http_requests_total",
		Help: "Total HTTP requests handled, by method, route and status code.",
	}, []string{"method", "route", "status"})

	// HTTPDuration is the request-latency histogram (the "Duration" of RED).
	HTTPDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "spm_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds, by method, route and status code.",
		Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
	}, []string{"method", "route", "status"})

	// HTTPInFlight is the number of requests currently being served.
	HTTPInFlight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "spm_http_requests_in_flight",
		Help: "Number of HTTP requests currently being served.",
	})

	// workerHeartbeat records the unix timestamp of each worker's last successful tick.
	workerHeartbeat = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "spm_worker_last_success_timestamp_seconds",
		Help: "Unix timestamp of the last successful run of a background worker.",
	}, []string{"worker"})

	buildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "spm_build_info",
		Help: "Build information; constant 1, labels carry the values.",
	}, []string{"version"})
)

var buildInfoOnce sync.Once

// SetBuildInfo records the running version as a labelled constant gauge.
func SetBuildInfo(version string) {
	buildInfoOnce.Do(func() { buildInfo.WithLabelValues(version).Set(1) })
}

// WorkerHeartbeat marks a worker as having completed a successful unit of work now.
func WorkerHeartbeat(name string) {
	workerHeartbeat.WithLabelValues(name).SetToCurrentTime()
}

// WorkerHeartbeatSeconds reads back a worker's last-heartbeat timestamp, 0 when
// it has never reported. Exported for tests: the property worth asserting is
// that a worker reports liveness at all, because a queue that has stopped and
// one that is merely idle produce identical counters.
func WorkerHeartbeatSeconds(name string) float64 {
	var m dto.Metric
	g, err := workerHeartbeat.GetMetricWithLabelValues(name)
	if err != nil {
		return 0
	}
	if err := g.Write(&m); err != nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

// Handler returns the Prometheus exposition HTTP handler for /metrics.
func Handler() http.Handler { return promhttp.Handler() }

// RegisterDBStats wires the sql.DB connection-pool stats into the registry as
// gauges, refreshed on each scrape via a custom collector.
func RegisterDBStats(db *sql.DB) {
	prometheus.MustRegister(&dbStatsCollector{db: db})
}

type dbStatsCollector struct{ db *sql.DB }

var (
	descOpen     = prometheus.NewDesc("spm_db_connections_open", "Open database connections (in-use + idle).", nil, nil)
	descInUse    = prometheus.NewDesc("spm_db_connections_in_use", "Database connections currently in use.", nil, nil)
	descIdle     = prometheus.NewDesc("spm_db_connections_idle", "Idle database connections.", nil, nil)
	descWaitCnt  = prometheus.NewDesc("spm_db_wait_count_total", "Total number of connection waits.", nil, nil)
	descWaitSecs = prometheus.NewDesc("spm_db_wait_seconds_total", "Total time blocked waiting for a connection, in seconds.", nil, nil)
)

func (c *dbStatsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- descOpen
	ch <- descInUse
	ch <- descIdle
	ch <- descWaitCnt
	ch <- descWaitSecs
}

func (c *dbStatsCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.db.Stats()
	ch <- prometheus.MustNewConstMetric(descOpen, prometheus.GaugeValue, float64(s.OpenConnections))
	ch <- prometheus.MustNewConstMetric(descInUse, prometheus.GaugeValue, float64(s.InUse))
	ch <- prometheus.MustNewConstMetric(descIdle, prometheus.GaugeValue, float64(s.Idle))
	ch <- prometheus.MustNewConstMetric(descWaitCnt, prometheus.CounterValue, float64(s.WaitCount))
	ch <- prometheus.MustNewConstMetric(descWaitSecs, prometheus.CounterValue, s.WaitDuration.Seconds())
}

// Blacklist export outcome. A failed export leaves Squid enforcing a stale ACL
// while the API reports success, so it must be alertable rather than a log line
// (SECURE-ERR-05, SECURE-OBS-01).
var (
	exportTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "spm_blacklist_export_total",
		Help: "Blacklist exports to /config, by outcome.",
	}, []string{"outcome"})
	exportLastSuccess = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "spm_blacklist_export_last_success_timestamp_seconds",
		Help: "Unix timestamp of the last successful blacklist export.",
	})
)

// ExportSuccess records a successful export.
func ExportSuccess() {
	exportTotal.WithLabelValues("success").Inc()
	exportLastSuccess.SetToCurrentTime()
}

// ExportFailure records a failed export.
func ExportFailure() { exportTotal.WithLabelValues("failure").Inc() }

// Proxied traffic. The metric set covered this backend's own HTTP surface, its
// workers, its build and its database pool — and nothing derived from
// proxy_logs, so the product's PRIMARY outcome (a request was proxied, a
// blacklisted destination was refused) had no series behind it. That is the one
// number that would reveal most of the silent failures in this system: a failed
// export, a dead watchdog, a truncated ACL and disabled retention all show up
// as the block rate or the request rate going to zero (SECURE-OBS-01).
var proxyRequests = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "spm_proxy_requests_total",
	Help: "Requests seen by the proxy, by outcome (allowed or blocked).",
}, []string{"outcome"})

// ProxyRequest records one ingested proxy log line.
func ProxyRequest(blocked bool) {
	if blocked {
		proxyRequests.WithLabelValues("blocked").Inc()
		return
	}
	proxyRequests.WithLabelValues("allowed").Inc()
}

// What the cache did with each proxied request, and how many bytes the proxy
// sent back for it, by the classes of workers.CacheOutcome. Every line of the
// access log is counted, the stack's own requests included, as
// spm_proxy_requests_total counts them. A hit ratio over any window is
// rate(hit + revalidated) / rate(hit + revalidated + miss): tunnels are not
// cacheable, so they are left out of it.
var (
	proxyCacheRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "spm_proxy_cache_requests_total",
		Help: "Proxied requests by what the cache did (hit, revalidated, miss, tunnel, refused, other).",
	}, []string{"outcome"})
	proxyCacheBytes = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "spm_proxy_cache_bytes_total",
		Help: "Bytes the proxy sent to clients, by what the cache did (hit, revalidated, miss, tunnel, refused, other).",
	}, []string{"outcome"})
)

// InitProxyCache creates the series of every outcome at 0, so a rate over
// them exists before the first request of each kind.
func InitProxyCache(outcomes []string) {
	for _, o := range outcomes {
		proxyCacheRequests.WithLabelValues(o)
		proxyCacheBytes.WithLabelValues(o)
	}
}

// ProxyCache records one ingested proxy log line by its cache outcome.
func ProxyCache(outcome string, bytes int64) {
	proxyCacheRequests.WithLabelValues(outcome).Inc()
	if bytes > 0 {
		proxyCacheBytes.WithLabelValues(outcome).Add(float64(bytes))
	}
}

// ProxyCacheCount is the request counter of one outcome, for tests.
func ProxyCacheCount(outcome string) float64 {
	m := &dto.Metric{}
	if err := proxyCacheRequests.WithLabelValues(outcome).Write(m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// CacheStore is what the proxy last read from Squid about its store. A nil
// field is one Squid did not print; its gauge is left out.
type CacheStore struct {
	AgeS           int64
	DiskUsedKB     *int64
	DiskCapacityKB *int64
	MemoryUsedKB   *int64
	Objects        *int64
}

// RegisterCacheStore exposes the proxy's cache store on every scrape, from
// read. read reports false when the proxy has written nothing readable; the
// gauges are then absent rather than 0. Squid's own hit ratios are not
// exported: they restart from 0 with Squid and disagree with each other (a
// request ratio of 0.0% next to a byte ratio of 68.4% on the same proxy),
// so spm_proxy_cache_*_total is the series to compute a ratio from.
func RegisterCacheStore(read func() (CacheStore, bool)) {
	prometheus.MustRegister(&cacheStoreCollector{read: read})
}

type cacheStoreCollector struct{ read func() (CacheStore, bool) }

var (
	descCacheAge     = prometheus.NewDesc("spm_squid_cache_stats_age_seconds", "Seconds since the proxy last read its cache statistics from Squid.", nil, nil)
	descCacheDisk    = prometheus.NewDesc("spm_squid_cache_disk_used_bytes", "Bytes the proxy's disk cache holds.", nil, nil)
	descCacheDiskMax = prometheus.NewDesc("spm_squid_cache_disk_capacity_bytes", "Size of the proxy's disk cache (cache_dir).", nil, nil)
	descCacheMemory  = prometheus.NewDesc("spm_squid_cache_memory_used_bytes", "Bytes the proxy's memory cache holds.", nil, nil)
	descCacheEntries = prometheus.NewDesc("spm_squid_cache_objects", "Objects in the proxy's cache (Squid's StoreEntries).", nil, nil)
	cacheStoreGauges = []*prometheus.Desc{descCacheAge, descCacheDisk, descCacheDiskMax, descCacheMemory, descCacheEntries}
)

func (c *cacheStoreCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range cacheStoreGauges {
		ch <- d
	}
}

func (c *cacheStoreCollector) Collect(ch chan<- prometheus.Metric) {
	s, ok := c.read()
	if !ok {
		return
	}
	ch <- prometheus.MustNewConstMetric(descCacheAge, prometheus.GaugeValue, float64(s.AgeS))
	kib := func(d *prometheus.Desc, v *int64) {
		if v != nil {
			ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, float64(*v)*1024)
		}
	}
	kib(descCacheDisk, s.DiskUsedKB)
	kib(descCacheDiskMax, s.DiskCapacityKB)
	kib(descCacheMemory, s.MemoryUsedKB)
	if s.Objects != nil {
		ch <- prometheus.MustNewConstMetric(descCacheEntries, prometheus.GaugeValue, float64(*s.Objects))
	}
}

// Log forwarding to a syslog server or SIEM (internal/logforward). An event
// is sent, dropped (the queue was full, or forwarding was switched off with
// events waiting), or failed (its write failed); a connection attempt that
// fails is counted on its own. The queue length shows a target falling
// behind before events are dropped.
const (
	LogForwardSent          = "sent"
	LogForwardDropped       = "dropped"
	LogForwardFailed        = "failed"
	LogForwardConnectFailed = "connect_failed"
)

var (
	logForwardEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "spm_log_forward_events_total",
		Help: "Events for the log forwarding target, by outcome (sent, dropped, failed, connect_failed).",
	}, []string{"outcome"})
	logForwardConnected = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "spm_log_forward_connected",
		Help: "1 while the log forwarder holds a connection to its target, 0 otherwise.",
	})
	logForwardQueue = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "spm_log_forward_queue_length",
		Help: "Events waiting to be sent to the log forwarding target.",
	})
	logForwardLastSent = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "spm_log_forward_last_sent_timestamp_seconds",
		Help: "Unix time of the last event sent to the log forwarding target.",
	})
)

func init() {
	for _, o := range []string{LogForwardSent, LogForwardDropped, LogForwardFailed, LogForwardConnectFailed} {
		logForwardEvents.WithLabelValues(o)
	}
}

// LogForward counts one event, or one connection attempt, by outcome.
func LogForward(outcome string) {
	logForwardEvents.WithLabelValues(outcome).Inc()
	if outcome == LogForwardSent {
		logForwardLastSent.SetToCurrentTime()
	}
}

// LogForwardCount is the counter of one outcome, for tests.
func LogForwardCount(outcome string) float64 {
	m := &dto.Metric{}
	if err := logForwardEvents.WithLabelValues(outcome).Write(m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// LogForwardConnected records whether the forwarder holds a connection.
func LogForwardConnected(up bool) {
	if up {
		logForwardConnected.Set(1)
		return
	}
	logForwardConnected.Set(0)
}

// LogForwardQueue records how many events wait.
func LogForwardQueue(n int) { logForwardQueue.Set(float64(n)) }

// Notification delivery. The channel by which an operator learns about security
// events reported its own failures as log lines only, so an expired token or a
// rotated webhook left a system that looks entirely healthy and simply stops
// telling anyone when something is attacked (SECURE-OBS-02).
var (
	notificationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "spm_notifications_total",
		Help: "Notification delivery attempts, by channel and outcome.",
	}, []string{"channel", "outcome"})
	notificationLastSuccess = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "spm_notification_last_success_timestamp_seconds",
		Help: "Unix timestamp of the last successful delivery, per channel.",
	}, []string{"channel"})
)

// NotificationSent records a successful delivery on a channel.
func NotificationSent(channel string) {
	notificationsTotal.WithLabelValues(channel, "success").Inc()
	notificationLastSuccess.WithLabelValues(channel).SetToCurrentTime()
}

// NotificationFailed records a failed delivery on a channel.
func NotificationFailed(channel string) {
	notificationsTotal.WithLabelValues(channel, "failure").Inc()
}

// NotificationDropped records an alert discarded because the queue was full.
func NotificationDropped() {
	notificationsTotal.WithLabelValues("queue", "dropped").Inc()
}

// Alerts the notification limits held back on purpose (Settings > Alerts), as
// opposed to dropped: grouped is an event counted into its group's digest
// instead of being sent on its own, cap is one channel's delivery held because
// the channel reached its hourly limit (the held-back notice reports them).
//
// Every series carries both labels, so the label set never changes: cap is
// counted per channel, and grouped, which happens before an event is split
// into channels, carries channel="all" (HeldAllChannels).
var notificationsHeld = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "spm_notifications_held_total",
	Help: "Alerts held back by the notification limits, by reason (grouped into a digest, " +
		"or over a channel's hourly cap) and channel (all for grouped).",
}, []string{"reason", "channel"})

// HeldAllChannels is the channel label of a grouped alert, which is held
// before it is split into channels.
const HeldAllChannels = "all"

// NotificationHeld records one alert held back for reason ("grouped" with
// HeldAllChannels, or "cap" with the channel that held it).
func NotificationHeld(reason, channel string) {
	notificationsHeld.WithLabelValues(reason, channel).Inc()
}

// NotificationsHeldCount is the current value of the held-back counter for
// reason and channel, for tests.
func NotificationsHeldCount(reason, channel string) float64 {
	var m dto.Metric
	c, err := notificationsHeld.GetMetricWithLabelValues(reason, channel)
	if err != nil {
		return 0
	}
	if err := c.Write(&m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

// Log retention. It is the only bound on the growth of proxy_logs, and it could
// be switched off by an unparseable setting value with no signal at all — the
// worker still emitted its heartbeat and the success line only fired when rows
// were actually deleted (SECURE-SCAL-03).
var (
	retentionLastRun = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "spm_log_retention_last_run_timestamp_seconds",
		Help: "Unix timestamp of the last retention pass that actually ran.",
	})
	retentionEnabled = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "spm_log_retention_enabled",
		Help: "1 when retention is configured and running, 0 when it is not pruning.",
	})
	retentionDays = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "spm_log_retention_days",
		Help: "Configured retention window in days.",
	})
)

// RetentionRan records a retention pass that executed with the given window.
func RetentionRan(days int) {
	retentionLastRun.SetToCurrentTime()
	retentionEnabled.Set(1)
	retentionDays.Set(float64(days))
}

// Database integrity. The full PRAGMA integrity_check runs after start-up
// (workers.StartIntegrityCheck), so its outcome is reported here and by
// readiness instead of by refusing to start.
var (
	dbIntegrityOK = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "spm_db_integrity_ok",
		Help: "1 when the last full PRAGMA integrity_check passed, 0 when it found a problem.",
	})
	dbIntegrityLastCheck = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "spm_db_integrity_last_check_timestamp_seconds",
		Help: "Unix timestamp of the last full PRAGMA integrity_check that completed.",
	})
)

// IntegrityChecked records the outcome of a completed full integrity check.
func IntegrityChecked(ok bool) {
	dbIntegrityLastCheck.SetToCurrentTime()
	if ok {
		dbIntegrityOK.Set(1)
	} else {
		dbIntegrityOK.Set(0)
	}
}

// RetentionDisabled records that retention is configured in a way that prunes
// nothing, so proxy_logs is growing without bound.
func RetentionDisabled() {
	retentionEnabled.Set(0)
	retentionDays.Set(0)
}

// WAF reconciler. The worker that re-pushes the stored heuristic configuration
// to a restarted WAF used to report nothing: no heartbeat, no counters, and no
// log line when the WAF was unreachable, so it could stop, or never reach the
// WAF, while the Settings page went on showing toggles the WAF no longer had
// (SECURE-OBS-01).
var (
	wafReconcileTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "spm_waf_reconcile_total",
		Help: "WAF reconciliation passes, by outcome: success, unreachable, push_failed.",
	}, []string{"outcome"})
	wafReconcileLastSuccess = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "spm_waf_reconcile_last_success_timestamp_seconds",
		Help: "Unix timestamp of the last pass after which the WAF matched the stored configuration.",
	})
)

func init() {
	// Create the series at zero so a rule on increase() sees them from the start.
	for _, o := range []string{"success", "unreachable", "push_failed"} {
		wafReconcileTotal.WithLabelValues(o)
	}
}

// WAFReconcile records the outcome of one reconciliation pass.
func WAFReconcile(outcome string) {
	wafReconcileTotal.WithLabelValues(outcome).Inc()
	if outcome == "success" {
		wafReconcileLastSuccess.SetToCurrentTime()
	}
}

// WAFReconcileCount reads a pass counter back, for tests.
func WAFReconcileCount(outcome string) float64 {
	m := &dto.Metric{}
	if err := wafReconcileTotal.WithLabelValues(outcome).Write(m); err != nil {
		return 0
	}
	return m.GetCounter().GetValue()
}

var (
	egressProviderRefreshTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "spm_egress_provider_refresh_total",
		Help: "Egress provider refresh attempts, by outcome: success, held, failure.",
	}, []string{"outcome"})
	egressProviderEntries = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "spm_egress_provider_entries",
		Help: "Stored CIDR entries for an egress provider, by provider name and IP family (4 or 6).",
	}, []string{"provider", "family"})
)

// EgressProviderRefresh records the outcome of one egress provider refresh ("success", "held", or "failure").
func EgressProviderRefresh(outcome string) {
	egressProviderRefreshTotal.WithLabelValues(outcome).Inc()
}

// SetEgressProviderEntries updates the per-family entry count gauges for a provider.
func SetEgressProviderEntries(provider string, v4Count, v6Count int) {
	egressProviderEntries.WithLabelValues(provider, "4").Set(float64(v4Count))
	egressProviderEntries.WithLabelValues(provider, "6").Set(float64(v6Count))
}

// DeleteEgressProviderEntries removes the entry count gauges for a deleted provider.
func DeleteEgressProviderEntries(provider string) {
	egressProviderEntries.DeleteLabelValues(provider, "4")
	egressProviderEntries.DeleteLabelValues(provider, "6")
}
