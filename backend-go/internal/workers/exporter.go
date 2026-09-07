package workers

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
)

// Exporter owns the blacklist export. It replaces the eight detached
// `go propagate(...)` spawns, which had no context, no owner, no concurrency
// bound and no way to be drained on shutdown, and which multiplied the window
// in which two exports raced over the same files (SECURE-CONC-03).
//
// Requests coalesce: the signal channel has capacity one, so N mutations
// arriving together collapse into a single export instead of N concurrent
// full-table scans.
type Exporter struct {
	db        *sql.DB
	configDir string
	signal    chan struct{}
}

// exporter is the process-wide instance, set once by Start. Handlers reach it
// through RequestExport.
var exporter *Exporter

// StartExporter wires the exporter to the worker context so shutdown can stop
// and drain it like every other background worker.
func StartExporter(ctx context.Context, db *sql.DB, configDir string) *Exporter {
	e := &Exporter{db: db, configDir: configDir, signal: make(chan struct{}, 1)}
	exporter = e
	track(func() {
		for {
			select {
			case <-ctx.Done():
				log.Info().Msg("blacklist exporter stopping")
				return
			case <-e.signal:
				metrics.WorkerHeartbeat("blacklist_exporter")
				if err := database.ExportBlacklistsToFiles(e.db, e.configDir); err != nil {
					// Surfaced as a metric as well as a log line: a failed
					// export means Squid keeps enforcing the previous list
					// while the UI shows the new one (SECURE-ERR-05).
					metrics.ExportFailure()
					log.Error().Err(err).Msg("blacklist export failed — the proxy is enforcing a stale list")
					continue
				}
				metrics.ExportSuccess()
				// Squid picks the lists up itself: the proxy-side watchdog polls
				// the mtime of the files just written and runs `squid -k
				// reconfigure`. dnsmasq has no such poll, so it needs an
				// explicit trigger.
				if err := e.signalDNSReload(); err != nil {
					log.Warn().Err(err).Msg("dns reload trigger failed")
				}
			}
		}
	})
	log.Info().Msg("blacklist exporter started")
	return e
}

// Request asks for an export. It never blocks: if one is already pending the
// signal is already queued and this mutation will be covered by it.
func (e *Exporter) Request() {
	select {
	case e.signal <- struct{}{}:
	default:
	}
}

// signalDNSReload touches the trigger the dns container watches. Squid needs no
// equivalent — its watchdog polls the exported files directly.
func (e *Exporter) signalDNSReload() error {
	// #nosec G306 — reload trigger, must be readable by the dns container
	return os.WriteFile(
		filepath.Join(e.configDir, ".reload-dns"),
		[]byte(strconv.FormatInt(time.Now().Unix(), 10)),
		0644,
	)
}

// RequestExport is the package-level entry point for handlers.
func RequestExport() {
	if exporter != nil {
		exporter.Request()
	}
}
