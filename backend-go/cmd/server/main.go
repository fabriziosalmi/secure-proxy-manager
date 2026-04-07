// Command server is the Go entry-point for the Secure Proxy Manager backend.
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strconv"
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
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/docker"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/handlers"
	appMW "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	ws "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/websocket"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
)

func main() {
	if err := run(); err != nil {
		log.Fatal().Err(err).Msg("application failed")
	}
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
		// #nosec G704
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", portNum))
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

	// Load bcrypt hash from DB so auth uses it instead of plaintext env-var.
	var dbHash string
	if err := db.QueryRow("SELECT password FROM users WHERE username = ?", cfg.AdminUsername).Scan(&dbHash); err == nil && dbHash != "" {
		cfg.AdminPasswordHash = dbHash
	}

	// ── services ─────────────────────────────────────────────────────────────
	authSvc := auth.NewService(cfg, db)
	dockerClient := docker.New()
	hub := ws.NewHub()
	notify := handlers.NewNotifyQueue(db, cfg.EncryptionKey)

	// ── background workers ───────────────────────────────────────────────────
	workerCtx, workerCancel := context.WithCancel(context.Background())
	defer workerCancel()
	workers.StartLogTailer(workerCtx, db, cfg.LogPath, hub)
	workers.StartLogRetention(workerCtx, db)
	workers.StartBlacklistRefresh(workerCtx, db, cfg.ConfigDir)
	workers.StartUpdateChecker(workerCtx, "")
	workers.CheckSquidCVEs()

	// ── router ───────────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(appMW.RequestID)
	r.Use(appMW.CORS(cfg))
	r.Use(appMW.SecurityHeaders)
	r.Use(appMW.GlobalRateLimit(20, 60))       // 20 req/s sustained, 60 burst per IP
	r.Use(appMW.MaxBodySize(55 * 1024 * 1024)) // 55MB max (for large blacklist imports)

	authMW := appMW.Auth(authSvc)

	// Register handler groups.
	handlers.NewAuthHandlers(db, authSvc, cfg, notify, hub).Register(r)
	handlers.NewLogHandlers(db).Register(r, authMW)
	handlers.NewSettingsHandlers(db, cfg).Register(r, authMW)
	handlers.NewBlacklistHandlers(db, cfg).Register(r, authMW)
	handlers.NewSecurityHandlers(db, authSvc, cfg, notify).Register(r, authMW)
	handlers.NewMaintenanceHandlers(db, cfg, dockerClient).Register(r, authMW)
	handlers.NewAnalyticsHandlers(db, cfg, dockerClient).Register(r, authMW)
	handlers.NewDatabaseHandlers(db).Register(r, authMW)
	handlers.NewDNSDetectHandlers(db).Register(r, authMW)
	handlers.RegisterAPIDocs(r, authMW)

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
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true // non-browser clients (curl, etc.)
			}
			if _, ok := wsAllowed[origin]; ok {
				return true
			}
			// Allow WebSocket from the same host the request arrived on
			// (covers IP-based access where CORS_ALLOWED_ORIGINS lists only localhost).
			if r.Host != "" {
				for _, scheme := range []string{"https://", "http://"} {
					if origin == scheme+r.Host {
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
			token := req.URL.Query().Get("token")
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
	workerCancel() // stop background workers first
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("shutdown error")
	}
	log.Info().Msg("shutdown complete")
	return nil
}
