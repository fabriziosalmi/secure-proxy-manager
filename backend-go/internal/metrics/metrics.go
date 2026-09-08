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

// RetentionDisabled records that retention is configured in a way that prunes
// nothing, so proxy_logs is growing without bound.
func RetentionDisabled() {
	retentionEnabled.Set(0)
	retentionDays.Set(0)
}
