// Package config loads runtime configuration from environment variables.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Config holds all runtime configuration values.
type Config struct {
	// Auth / JWT
	AdminUsername     string
	AdminPassword     string // plaintext only for initial / legacy auth
	AdminPasswordHash string // bcrypt hash loaded from DB at runtime (optional)
	SecretKey         string
	JWTExpireDuration time.Duration
	MaxAttempts       int
	RateLimitWindow   time.Duration

	// Network
	Port               string
	CORSAllowedOrigins []string
	ProxyHost          string

	// Filesystem
	DatabasePath string
	ConfigDir    string
	LogPath      string
	DNSLogPath   string

	// Internal component URLs (for WAF/Proxy communication)
	WAFURL         string
	WAFServiceUser string // dedicated service credential for WAF management API
	WAFServicePass string // separate from AdminPassword so password changes don't break WAF calls
	ProxyURL       string
	GeoIPURL       string

	// AlertToken authenticates the WAF when it posts to /api/internal/alert.
	// It exists so the WAF does not need the admin credential: that container
	// is the one that parses attacker-controlled request bodies, and holding
	// BASIC_AUTH_PASSWORD gave it full control of the management API
	// (SECURE-AUTH-02). Empty means no token is configured, and the endpoint
	// keeps accepting admin auth so an in-place upgrade does not lose alerts.
	AlertToken string

	// Encryption key for sensitive settings (hex-encoded 32 bytes)
	EncryptionKey string
}

// Load reads environment variables and returns a validated Config.
// It panics on missing required variables.
func Load() *Config {
	username := requireEnv("BASIC_AUTH_USERNAME")
	password := requireEnv("BASIC_AUTH_PASSWORD")
	validatePasswordComplexity(password)

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
		AdminUsername:      username,
		AdminPassword:      password,
		SecretKey:          loadOrGenerateSecret(),
		JWTExpireDuration:  jwtExp,
		MaxAttempts:        maxAttempts,
		RateLimitWindow:    time.Duration(rateLimitSec) * time.Second,
		Port:               envOrDefault("PORT", "5000"),
		CORSAllowedOrigins: cleanCors,
		ProxyHost:          envOrDefault("PROXY_HOST", "proxy"),
		DatabasePath:       envOrDefault("DATABASE_PATH", "/data/proxy_manager.db"),
		ConfigDir:          envOrDefault("CONFIG_DIR", "/config"),
		LogPath:            envOrDefault("LOG_PATH", "/logs/access.log"),
		DNSLogPath:         envOrDefault("DNS_LOG_PATH", "/logs/dnsmasq.log"),
		WAFURL:             envOrDefault("WAF_URL", "http://waf:8080"),
		// WAF_SERVICE_USERNAME/PASSWORD default to BASIC_AUTH_* so existing
		// single-credential deployments work unchanged. Set the WAF_SERVICE_*
		// vars to a dedicated service account to decouple the human admin
		// password from inter-service auth (e.g. after an admin password change).
		WAFServiceUser: envOrDefault("WAF_SERVICE_USERNAME", username),
		WAFServicePass: envOrDefault("WAF_SERVICE_PASSWORD", password),
		ProxyURL:       envOrDefault("PROXY_URL", "http://proxy:3128"),
		AlertToken:     strings.TrimSpace(os.Getenv("INTERNAL_ALERT_TOKEN")),
		GeoIPURL:       envOrDefault("GEOIP_URL", ""), // Empty means use defaults
		EncryptionKey:  loadOrGenerateEncKey(),
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

// validatePasswordComplexity ensures the admin password meets minimum security
// requirements at startup. Prevents deployment with trivially guessable passwords.
func validatePasswordComplexity(password string) {
	commonDefaults := []string{"changeme", "password", "admin", "secret", "test", "12345678", "qwerty"}
	lower := strings.ToLower(password)
	for _, weak := range commonDefaults {
		if lower == weak {
			log.Fatal().Msg("BASIC_AUTH_PASSWORD is a common default — choose a stronger password")
		}
	}
	if len(password) < 8 {
		log.Fatal().Int("length", len(password)).Msg("BASIC_AUTH_PASSWORD must be at least 8 characters")
	}
}

// knownWeakSecrets are example/dev SECRET_KEY values shipped in docs, compose
// files or commonly copy-pasted. A predictable JWT secret lets an attacker forge
// admin session tokens, so we refuse to boot with one (compared case-folded).
var knownWeakSecrets = map[string]struct{}{
	"dev_secret_key_change_in_production": {},
	"change_in_production":                {},
	"changeme":                            {},
	"change_me":                           {},
	"secret":                              {},
	"secret_key":                          {},
	"your_secret_key_here":                {},
	"please_change_me":                    {},
	"supersecret":                         {},
}

// secretKeyStrengthError returns a non-nil error if the operator-supplied JWT
// secret is predictable (known example value, too short, or too low entropy).
// Split out from the fatal wrapper so the policy is unit-testable without
// os.Exit. An empty SECRET_KEY is handled separately by loadOrGenerateSecret
// (auto-generate), so this only runs on operator-supplied values.
func secretKeyStrengthError(secret string) error {
	const minLen = 32
	if _, bad := knownWeakSecrets[strings.ToLower(strings.TrimSpace(secret))]; bad {
		return fmt.Errorf("SECRET_KEY is a known example/default value — set a unique random secret (generate one with `openssl rand -hex 32`)")
	}
	if len(secret) < minLen {
		return fmt.Errorf("SECRET_KEY is too short (%d chars) — use at least %d (`openssl rand -hex 32`)", len(secret), minLen)
	}
	distinct := make(map[rune]struct{}, len(secret))
	for _, r := range secret {
		distinct[r] = struct{}{}
	}
	if len(distinct) < 8 {
		return fmt.Errorf("SECRET_KEY has too little entropy (%d distinct characters) — generate one with `openssl rand -hex 32`", len(distinct))
	}
	return nil
}

// validateSecretKeyStrength fails the process closed on a predictable JWT secret,
// mirroring validatePasswordComplexity — a weak secret forges every session token.
func validateSecretKeyStrength(secret string) {
	if err := secretKeyStrengthError(secret); err != nil {
		log.Fatal().Msg(err.Error())
	}
}

// stateDir is where the JWT secret and the encryption key live: the directory
// holding the database, so the three pieces of persistent state move together.
func stateDir() string {
	return filepath.Dir(envOrDefault("DATABASE_PATH", "/data/proxy_manager.db"))
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// encryptionKeyError returns a non-nil error if an operator-supplied
// ENCRYPTION_KEY is not exactly 32 bytes of hex. Split out from the fatal
// wrapper so the policy is unit-testable without os.Exit, mirroring
// secretKeyStrengthError.
func encryptionKeyError(key string) error {
	raw, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("ENCRYPTION_KEY is not valid hex (%d chars) — generate one with `openssl rand -hex 32`", len(key))
	}
	if len(raw) != 32 {
		return fmt.Errorf("ENCRYPTION_KEY must decode to 32 bytes, got %d (%d hex chars) — generate one with `openssl rand -hex 32`", len(raw), len(key))
	}
	return nil
}

// loadOrGenerateEncKey reads the encryption key from env → file → auto-generate.
func loadOrGenerateEncKey() string {
	// A key the operator explicitly supplied is either used or refused; it is
	// never silently discarded in favour of a generated one. Falling through
	// would encrypt under a key they do not hold, making their restore plan
	// fail, or generate and persist a new one so that correcting the variable
	// later renders every existing value undecryptable (SECURE-CONF-01).
	if s := os.Getenv("ENCRYPTION_KEY"); s != "" {
		if err := encryptionKeyError(s); err != nil {
			log.Fatal().Msg(err.Error())
		}
		return s
	}
	// Derived from the database directory, not hardcoded. DATABASE_PATH is
	// configurable, so relocating the database used to leave these two keys
	// behind in an unmounted /data: the loaders warned and continued, and every
	// restart then rotated both — invalidating every session and making every
	// previously encrypted setting undecryptable (SECURE-CONF-04).
	encFile := filepath.Join(stateDir(), ".enc_key")
	data, err := os.ReadFile(encFile)
	if err == nil && len(strings.TrimSpace(string(data))) == 64 {
		return strings.TrimSpace(string(data))
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatal().Err(err).Msg("cannot generate encryption key")
	}
	key := hex.EncodeToString(b)
	// Persist so the same key is reused across restarts. Failure here means
	// every container restart will rotate the key, making any data encrypted
	// with the previous key unrecoverable — that must not happen silently.
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		log.Warn().Err(err).Str("dir", stateDir()).Msg("encryption key: cannot create the state directory — key will not survive restart")
		return key
	}
	if err := os.WriteFile(encFile, []byte(key), 0o600); err != nil {
		log.Warn().Err(err).Str("path", encFile).Msg("encryption key: cannot persist — key will not survive restart")
	}
	return key
}

// loadOrGenerateSecret reads the JWT secret from env → file → auto-generate.
func loadOrGenerateSecret() string {
	if s := os.Getenv("SECRET_KEY"); s != "" {
		validateSecretKeyStrength(s) // fail-closed on predictable secrets
		return s
	}
	jwtFile := filepath.Join(stateDir(), ".jwt_secret")
	data, err := os.ReadFile(jwtFile)
	if err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return strings.TrimSpace(string(data))
	}
	// Auto-generate and persist.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatal().Err(err).Msg("cannot generate JWT secret")
	}
	secret := hex.EncodeToString(b)
	// Persist so JWTs survive restart. If we can't, log it — every restart
	// will invalidate every active session otherwise.
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		log.Warn().Err(err).Str("dir", stateDir()).Msg("JWT secret: cannot create the state directory — sessions will not survive restart")
		return secret
	}
	if err := os.WriteFile(jwtFile, []byte(secret), 0o600); err != nil {
		log.Warn().Err(err).Str("path", jwtFile).Msg("JWT secret: cannot persist — sessions will not survive restart")
	}
	return secret
}
