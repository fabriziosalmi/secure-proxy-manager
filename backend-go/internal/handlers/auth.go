package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/config"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/middleware"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/models"
	ws "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/websocket"
	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/workers"

	"github.com/go-chi/chi/v5"
)

type AuthHandlers struct {
	db     *sql.DB
	svc    *auth.Service
	cfg    *config.Config
	notify NotifyQueue
	hub    *ws.Hub
}

func NewAuthHandlers(db *sql.DB, svc *auth.Service, cfg *config.Config, notify NotifyQueue, hub *ws.Hub) *AuthHandlers {
	return &AuthHandlers{db: db, svc: svc, cfg: cfg, notify: notify, hub: hub}
}

func (h *AuthHandlers) Register(r chi.Router) {
	authMW := middleware.Auth(h.svc)
	r.Post("/api/auth/login", h.Login)
	r.With(authMW).Post("/api/logout", h.Logout)
	r.With(authMW).Post("/api/change-password", h.ChangePassword)
	r.With(authMW).Get("/api/ws-token", h.WSToken)
	r.Get("/health", h.HealthLegacy)
	r.Get("/api/health", h.Health)
}

func (h *AuthHandlers) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password required")
		return
	}

	// Re-use authenticate which handles rate-limiting internally.
	tmpR, _ := http.NewRequest("GET", "/", nil)
	tmpR.Header.Set("Authorization", basicHeader(req.Username, req.Password))
	tmpR.RemoteAddr = r.RemoteAddr
	tmpR.Header.Set("X-Forwarded-For", r.Header.Get("X-Forwarded-For"))

	username, _, err := h.svc.Authenticate(tmpR)
	if err != nil {
		clientAddr := r.Header.Get("X-Forwarded-For")
		if clientAddr == "" {
			clientAddr = r.RemoteAddr
		}

		if err.Error() == "too many failed attempts, try again later" {
			h.alertLoginFailure(req.Username, clientAddr, "rate_limited")
			writeError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		h.alertLoginFailure(req.Username, clientAddr, "bad_credentials")
		writeError(w, http.StatusUnauthorized, "incorrect username or password")
		return
	}

	token, err := h.svc.IssueJWT(username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}
	database.Audit(h.db, username, "login", "", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "access_token": token, "token_type": "Bearer"})
}

func (h *AuthHandlers) Logout(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") && len(authHeader) > 7 {
		h.svc.RevokeJWT(authHeader[7:])
	}
	username, _ := r.Context().Value(middleware.CtxUsername).(string)
	database.Audit(h.db, username, "logout", "", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Logged out successfully"})
}

var pwdStrong = regexp.MustCompile(`[0-9]`)
var pwdSpecial = regexp.MustCompile(`[^a-zA-Z0-9]`)

func (h *AuthHandlers) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req models.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}
	if !pwdStrong.MatchString(req.NewPassword) || !pwdSpecial.MatchString(req.NewPassword) {
		writeError(w, http.StatusBadRequest, "password must contain at least one number and one special character")
		return
	}

	username, _ := r.Context().Value(middleware.CtxUsername).(string)

	var stored string
	if err := h.db.QueryRow("SELECT password FROM users WHERE username=?", username).Scan(&stored); err != nil {
		writeError(w, http.StatusInternalServerError, "user lookup failed")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(stored), []byte(req.CurrentPassword)) != nil {
		writeError(w, http.StatusBadRequest, "current password is incorrect")
		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	if _, err := h.db.Exec("UPDATE users SET password=? WHERE username=?", newHash, username); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	// Mark default password as changed in settings.
	_, _ = h.db.Exec(
		"INSERT OR REPLACE INTO settings(setting_name,setting_value) VALUES(?,?)",
		"default_password_changed", "true",
	)
	database.Audit(h.db, username, "change_password", "", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Password changed successfully"})
}

func (h *AuthHandlers) WSToken(w http.ResponseWriter, r *http.Request) {
	username, _ := r.Context().Value(middleware.CtxUsername).(string)
	token := h.svc.IssueWSToken(username)
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "token": token})
}

func (h *AuthHandlers) HealthLegacy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func (h *AuthHandlers) Health(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"status":  "healthy",
		"version": config.AppVersion,
		"runtime": "go",
	}
	upd := workers.GetUpdateInfo()
	if upd.Available {
		resp["update_available"] = upd.Latest
		resp["update_url"] = upd.URL
	}
	cve := workers.GetCVEInfo()
	if cve.Version != "" {
		resp["squid_version"] = cve.Version
		if len(cve.CVEs) > 0 {
			resp["squid_cves"] = len(cve.CVEs)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func basicHeader(u, p string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(u+":"+p))
}

// alertLoginFailure sends a login failure event to the notification pipeline
// and broadcasts it to connected WebSocket clients (admin dashboard).
func (h *AuthHandlers) alertLoginFailure(username, clientIP, reason string) {
	now := time.Now().Format(time.RFC3339)

	// Audit log entry for every failed attempt.
	database.Audit(h.db, username, "login_failed", clientIP, reason)

	event := map[string]any{
		"timestamp":  now,
		"event_type": "login_failure",
		"message":    "Failed login attempt for user '" + username + "' from " + clientIP,
		"level":      "warning",
		"client_ip":  clientIP,
		"username":   username,
		"reason":     reason,
	}

	// Push to notification queue (webhook, Gotify, Telegram, etc.)
	if h.notify != nil {
		select {
		case h.notify <- event:
		default:
		}
	}

	// Broadcast to WebSocket clients for real-time dashboard alert.
	if h.hub != nil {
		wsMsg, _ := json.Marshal(map[string]any{
			"type": "login_failure",
			"data": event,
		})
		select {
		case h.hub.Broadcast <- wsMsg:
		default:
		}
	}
}
