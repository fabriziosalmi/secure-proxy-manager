// Command server is the Go entry-point for the Secure Proxy Manager backend.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/handlers"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/metrics"
	appMW "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	ws "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/websocket"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

func main() {
	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("application failed")
	}
}

// wsTokenFromSubprotocol extracts the one-time auth token from the
// Sec-WebSocket-Protocol header. The client sends it as the subprotocol value
// "spm-ws-token.<hex-token>", keeping it out of the URL query string (and
// therefore out of server access logs, browser history, and Referer headers).
func wsTokenFromSubprotocol(req *http.Request) string {
	for _, proto := range websocket.Subprotocols(req) {
		const prefix = "spm-ws-token."
		if strings.HasPrefix(proto, prefix) {
			return proto[len(prefix):]
		}
	}
	return ""
}

func run() error {
	// ── healthcheck mode (for Docker HEALTHCHECK in distroless) ──────────────
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		port := os.Getenv("PORT")
		if port == "" {
			port = "5000"
		}
		// Strict parsing to prevent SSRF path manipulation via port var (G704 fix)
		portNum, err := strconv.Atoi(port)
		if err != nil || portNum <= 0 || portNum > 65535 {
			os.Exit(1)
		}
		// Probe readiness (DB reachable), not just liveness, so a wedged DB makes
		// the container report unhealthy instead of falsely healthy.
		// #nosec G107 -- localhost readiness probe; portNum is a validated
		// 1-65535 int (checked above) and the URL is not user input.
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/readyz", portNum))
		if err != nil || resp.StatusCode != 200 {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// ── logging ──────────────────────────────────────────────────────────────
	zerolog.TimeFieldFormat = time.RFC3339
	if os.Getenv("LOG_FORMAT") == "pretty" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})
	}

	// ── config ───────────────────────────────────────────────────────────────
	cfg := config.Load()
	log.Info().Str("version", config.AppVersion).Msg("secure-proxy-manager backend starting")

	// ── database ─────────────────────────────────────────────────────────────
	db, err := database.Open(cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer db.Close()

	adminHash, err := auth.HashPassword(cfg.AdminPassword)
	if err != nil {
		return err
	}
	if err := database.Init(db, cfg.AdminUsername, adminHash); err != nil {
		return err
	}

	// Reconcile the exported /config lists against the database before serving.
	//
	// The export is otherwise only a side effect of a mutation, performed by a
	// detached goroutine AFTER the handler has already returned 200. A crash in
	// that window — SIGKILL, OOM, host reboot, a container recreate — leaves the
	// row committed and the exported file stale, and nothing ever compares them
	// again: the UI lists the entry as blocked, Squid never blocks it, and the
	// divergence persists until the same list is mutated again or the (optional)
	// auto-refresh worker happens to fire. For a product whose function is
	// blocking, that is a silent, indefinite fail-open on the primary control.
	//
	// Fatal rather than a warning: if /config is unwritable the proxy would be
	// enforcing rules that no longer match the database, and refusing to start is
	// the only outcome that cannot be mistaken for working.
	if err := database.ExportBlacklistsToFiles(db, cfg.ConfigDir); err != nil {
		return fmt.Errorf("startup blacklist export to %s: %w", cfg.ConfigDir, err)
	}
	log.Info().Str("config_dir", cfg.ConfigDir).Msg("blacklists exported at startup (db → /config reconciled)")

	// Load bcrypt hash from DB so auth uses it instead of plaintext env-var.
	var dbHash string
	if err := db.QueryRow("SELECT password FROM users WHERE username = ?", cfg.AdminUsername).Scan(&dbHash); err == nil && dbHash != "" {
		cfg.AdminPasswordHash = dbHash
	}

	// ── services ─────────────────────────────────────────────────────────────
	authSvc := auth.NewService(cfg, db)
	hub := ws.NewHub()

	// ── background workers ───────────────────────────────────────────────────
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()

	// The notification queue is a worker like the six below: cancelled by the
	// same context and covered by the same drain, so shutdown does not silently
	// discard queued security alerts (SECURE-CONC-01).
	notify := handlers.NewNotifyQueue(workerCtx, db, cfg.EncryptionKey)
	workers.StartLogTailer(workerCtx, db, cfg.LogPath, filepath.Dir(cfg.DatabasePath), hub)
	workers.StartDNSTailer(workerCtx, db, cfg.DNSLogPath, filepath.Dir(cfg.DatabasePath), hub)
	workers.StartLogRetention(workerCtx, db)
	workers.StartBlacklistRefresh(workerCtx, db, cfg.ConfigDir)
	// Owns the blacklist export: coalesces concurrent requests, is bound to the
	// worker context so shutdown can stop it, and reports failure as a metric
	// (SECURE-CONC-03, SECURE-ERR-05).
	workers.StartExporter(workerCtx, db, cfg.ConfigDir)
	// Brings a restarted WAF back to the stored heuristic configuration; without
	// it a WAF restart silently reverted every toggle to the compose default
	// while the UI kept showing the operator's choice (SECURE-CONF-02).
	workers.StartWAFReconciler(workerCtx, db, cfg.WAFURL, cfg.WAFServiceUser, cfg.WAFServicePass)
	workers.StartUpdateChecker(workerCtx, "")
	workers.CheckSquidCVEs()

	// ── router ───────────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(appMW.RequestID)
	r.Use(appMW.Metrics)   // RED metrics per route (records after routing)
	r.Use(appMW.AccessLog) // one structured log line per request
	r.Use(appMW.CORS(cfg))
	r.Use(appMW.SecurityHeaders)
	r.Use(appMW.APIVersion)
	r.Use(appMW.GlobalRateLimit(20, 60))       // 20 req/s sustained, 60 burst per IP
	r.Use(appMW.MaxBodySize(55 * 1024 * 1024)) // 55MB max (for large blacklist imports)

	authMW := appMW.Auth(authSvc)

	// Without a dedicated token the WAF has to authenticate to
	// /api/internal/alert with the admin credential, which means the container
	// that parses attacker-controlled bodies holds full control of the
	// management API (SECURE-AUTH-02). We keep accepting it so an upgrade does
	// not silently stop delivering alerts, but say so once, loudly.
	if cfg.AlertToken == "" {
		log.Warn().Msg("INTERNAL_ALERT_TOKEN is not set: /api/internal/alert still accepts the admin credential, " +
			"so the WAF container needs BASIC_AUTH_PASSWORD. Set INTERNAL_ALERT_TOKEN (openssl rand -hex 32) " +
			"on both the backend and the waf service to scope it down.")
	}

	// Register handler groups.
	handlers.NewAuthHandlers(db, authSvc, cfg, notify, hub).Register(r)
	handlers.NewLogHandlers(db).Register(r, authMW)
	handlers.NewSettingsHandlers(db, cfg).Register(r, authMW)
	handlers.NewBlacklistHandlers(db, cfg).Register(r, authMW)
	handlers.NewSecurityHandlers(db, authSvc, cfg, notify).Register(r, authMW)
	handlers.NewMaintenanceHandlers(db, cfg).Register(r, authMW)
	handlers.NewAnalyticsHandlers(db, cfg).WithSysInfo(handlers.WorkerSysInfo{}).Register(r, authMW)
	handlers.NewDatabaseHandlers(db).Register(r, authMW)
	handlers.NewDNSDetectHandlers(db).Register(r, authMW)
	handlers.RegisterAPIDocs(r, authMW)

	// ── Prometheus metrics (internal network only; not proxied by nginx) ──────
	metrics.SetBuildInfo(config.AppVersion)
	metrics.RegisterDBStats(db)
	r.Handle("/metrics", metrics.Handler())

	// ── pprof (auth-protected) ───────────────────────────────────────────────
	r.Route("/debug/pprof", func(pr chi.Router) {
		pr.Use(authMW)
		pr.HandleFunc("/", pprof.Index)
		pr.HandleFunc("/cmdline", pprof.Cmdline)
		pr.HandleFunc("/profile", pprof.Profile)
		pr.HandleFunc("/symbol", pprof.Symbol)
		pr.HandleFunc("/trace", pprof.Trace)
		pr.Handle("/goroutine", pprof.Handler("goroutine"))
		pr.Handle("/heap", pprof.Handler("heap"))
		pr.Handle("/allocs", pprof.Handler("allocs"))
		pr.Handle("/block", pprof.Handler("block"))
		pr.Handle("/mutex", pprof.Handler("mutex"))
		pr.Handle("/threadcreate", pprof.Handler("threadcreate"))
	})

	// ── WebSocket ─────────────────────────────────────────────────────────────
	wsAllowed := make(map[string]struct{}, len(cfg.CORSAllowedOrigins))
	for _, o := range cfg.CORSAllowedOrigins {
		wsAllowed[o] = struct{}{}
	}
	upgrader := websocket.Upgrader{
		// No Subprotocols list here: gorilla's selectSubprotocol does exact
		// matching, and the client's offered value is "spm-ws-token.<token>"
		// (dynamic). We perform the subprotocol negotiation manually below.
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true // non-browser clients (curl, etc.)
			}
			if _, ok := wsAllowed[origin]; ok {
				return true
			}
			// Allow WebSocket from the same host the page was served from. Compare
			// HOSTNAMES (port-tolerant): the browser Origin carries the public port
			// (e.g. https://192.168.122.107:8443) but nginx forwards Host as $host
			// without the port, so an exact "scheme+host" match would wrongly fail
			// for IP-based access where CORS_ALLOWED_ORIGINS lists only localhost.
			if r.Host != "" {
				if ou, err := url.Parse(origin); err == nil && ou.Hostname() != "" {
					rh := r.Host
					if h, _, e := net.SplitHostPort(rh); e == nil {
						rh = h
					}
					if ou.Hostname() == rh {
						return true
					}
				}
			}
			return false
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	r.With(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			token := wsTokenFromSubprotocol(req)
			if token == "" {
				http.Error(w, "missing token", http.StatusUnauthorized)
				return
			}
			if _, ok := authSvc.ValidateWSToken(token); !ok {
				http.Error(w, "invalid or expired token", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, req)
		})
	}).Get("/api/ws/logs", func(w http.ResponseWriter, req *http.Request) {
		// The one-time token arrives in the client's Sec-WebSocket-Protocol
		// request header and is extracted/validated by the middleware above.
		// The server intentionally selects NO subprotocol: omitting
		// Sec-WebSocket-Protocol from the 101 response is valid per RFC 6455
		// §4.2.2, browsers accept it, and it avoids echoing the token at all.
		conn, err := upgrader.Upgrade(w, req, nil)
		if err != nil {
			log.Warn().Err(err).Msg("websocket upgrade failed")
			return
		}
		hub.Register(conn)
	})

	// ── HTTP server ───────────────────────────────────────────────────────────
	addr := ":" + cfg.Port
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Info().Str("addr", addr).Msg("HTTP server starting")

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// In test mode we might not want to fatal.
			// We'll just log error.
			log.Error().Err(err).Msg("server error")
		}
	}()

	// ── graceful shutdown ────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Allow for automated testing shutdown
	if os.Getenv("TEST_MODE") == "true" {
		time.Sleep(500 * time.Millisecond)
		log.Info().Msg("test mode: auto-shutting down")
		quit <- syscall.SIGTERM
	}

	<-quit
	log.Info().Msg("shutdown signal received")

	// Drain the HTTP server FIRST, so in-flight requests finish while the
	// workers they may depend on are still running. Cancelling the workers
	// first — as this did — meant a request still being served for up to five
	// more seconds ran against stopped workers (SECURE-CONC-02).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("shutdown error")
	}

	// Then stop the workers and actually WAIT for them. workerCancel only
	// closes a channel; without the wait the process could exit with a tailer
	// holding a read-but-uncommitted batch, losing it with no record.
	workerCancel()
	drained := make(chan struct{})
	go func() { workers.Wait(); close(drained) }()
	select {
	case <-drained:
		log.Info().Msg("background workers drained")
	case <-time.After(5 * time.Second):
		log.Warn().Msg("background workers did not drain within 5s — exiting anyway")
	}

	log.Info().Msg("shutdown complete")
	return nil
}
