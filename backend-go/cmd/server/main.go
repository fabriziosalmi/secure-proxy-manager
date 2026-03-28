// Command server is the Go entry-point for the Secure Proxy Manager backend.
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
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
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"
	ws "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/websocket"
)

func main() {
	// ── healthcheck mode (for Docker HEALTHCHECK in distroless) ──────────────
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		port := os.Getenv("PORT")
		if port == "" {
			port = "5000"
		}
		resp, err := http.Get("http://127.0.0.1:" + port + "/health")
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
		log.Fatal().Err(err).Msg("cannot open database")
	}
	defer db.Close()

	adminHash, err := auth.HashPassword(cfg.AdminPassword)
	if err != nil {
		log.Fatal().Err(err).Msg("cannot hash admin password")
	}
	if err := database.Init(db, cfg.AdminUsername, adminHash); err != nil {
		log.Fatal().Err(err).Msg("database init failed")
	}

	// ── services ─────────────────────────────────────────────────────────────
	authSvc := auth.NewService(cfg)
	dockerClient := docker.New()
	hub := ws.NewHub()
	notify := handlers.NewNotifyQueue(db)

	// ── background workers ───────────────────────────────────────────────────
	workers.StartLogTailer(db, cfg.LogPath, hub)
	workers.StartLogRetention(db)
	workers.StartBlacklistRefresh(db, cfg.ConfigDir)
	workers.StartUpdateChecker("")

	// ── router ───────────────────────────────────────────────────────────────
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(appMW.RequestID)
	r.Use(appMW.CORS(cfg))
	r.Use(appMW.SecurityHeaders)
	r.Use(appMW.MaxBodySize(55 * 1024 * 1024)) // 55MB max (for large blacklist imports)

	authMW := appMW.Auth(authSvc)

	// Register handler groups.
	handlers.NewAuthHandlers(db, authSvc, cfg).Register(r)
	handlers.NewLogHandlers(db).Register(r, authMW)
	handlers.NewSettingsHandlers(db).Register(r, authMW)
	handlers.NewBlacklistHandlers(db, cfg).Register(r, authMW)
	handlers.NewSecurityHandlers(db, authSvc, cfg, notify).Register(r, authMW)
	handlers.NewMaintenanceHandlers(db, cfg, dockerClient).Register(r, authMW)
	handlers.NewAnalyticsHandlers(db, cfg).Register(r, authMW)
	handlers.NewDatabaseHandlers(db).Register(r, authMW)

	// ── WebSocket ─────────────────────────────────────────────────────────────
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// One-time token validated below.
			return true
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
			log.Fatal().Err(err).Msg("server failed")
		}
	}()

	// ── graceful shutdown ────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Info().Msg("shutdown signal received")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("shutdown error")
	}
	log.Info().Msg("shutdown complete")
}
