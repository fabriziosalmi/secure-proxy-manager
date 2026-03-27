// Package config loads runtime configuration from environment variables.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Config holds all runtime configuration values.
type Config struct {
	// Auth / JWT
	AdminUsername     string
	AdminPassword     string        // plaintext only for initial / legacy auth
	AdminPasswordHash string        // bcrypt hash loaded from DB at runtime (optional)
	SecretKey         string
	JWTExpireDuration time.Duration
	MaxAttempts       int
	RateLimitWindow   time.Duration

	// Network
	Port           string
	CORSAllowedOrigins []string
	ProxyHost      string
	ProxyPort      string

	// Filesystem
	DatabasePath string
	ConfigDir    string
	LogPath      string
}

// Load reads environment variables and returns a validated Config.
// It panics on missing required variables.
func Load() *Config {
	username := requireEnv("BASIC_AUTH_USERNAME")
	password := requireEnv("BASIC_AUTH_PASSWORD")

	cors := strings.Split(envOrDefault("CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000"), ",")
	var cleanCors []string
	for _, o := range cors {
		o = strings.TrimSpace(o)
		if o != "" && o != "*" {
			cleanCors = append(cleanCors, o)
		}
	}

	jwtExp, err := time.ParseDuration(envOrDefault("JWT_EXPIRE_DURATION", "8h"))
	if err != nil {
		jwtExp = 8 * time.Hour
	}

	maxAttempts, _ := strconv.Atoi(envOrDefault("MAX_LOGIN_ATTEMPTS", "5"))
	if maxAttempts < 1 {
		maxAttempts = 5
	}
	rateLimitSec, _ := strconv.Atoi(envOrDefault("RATE_LIMIT_WINDOW_SECONDS", "300"))
	if rateLimitSec < 1 {
		rateLimitSec = 300
	}

	cfg := &Config{
		AdminUsername:     username,
		AdminPassword:     password,
		SecretKey:         loadOrGenerateSecret(),
		JWTExpireDuration: jwtExp,
		MaxAttempts:       maxAttempts,
		RateLimitWindow:   time.Duration(rateLimitSec) * time.Second,
		Port:              envOrDefault("PORT", "5000"),
		CORSAllowedOrigins: cleanCors,
		ProxyHost:         envOrDefault("PROXY_HOST", "proxy"),
		ProxyPort:         envOrDefault("PROXY_PORT", "3128"),
		DatabasePath:      envOrDefault("DATABASE_PATH", "/data/proxy_manager.db"),
		ConfigDir:         envOrDefault("CONFIG_DIR", "/config"),
		LogPath:           envOrDefault("LOG_PATH", "/logs/access.log"),
	}
	return cfg
}

func requireEnv(key string) string {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		log.Fatal().Str("env", key).Msg("required environment variable is not set")
	}
	return v
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// loadOrGenerateSecret reads the JWT secret from env → file → auto-generate.
func loadOrGenerateSecret() string {
	if s := os.Getenv("SECRET_KEY"); s != "" {
		return s
	}
	const secretFile = "/data/.jwt_secret"
	data, err := os.ReadFile(secretFile)
	if err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return strings.TrimSpace(string(data))
	}
	// Auto-generate and persist.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatal().Err(err).Msg("cannot generate JWT secret")
	}
	secret := hex.EncodeToString(b)
	if err := os.MkdirAll("/data", 0o700); err == nil {
		os.WriteFile(secretFile, []byte(secret), 0o600) //nolint:errcheck
	}
	return secret
}
