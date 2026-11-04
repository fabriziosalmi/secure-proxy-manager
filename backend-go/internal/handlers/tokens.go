package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/database"
)

// TokenHandlers create, list and revoke API tokens (database.APIToken). No
// token reaches these routes (auth.TokenAllows): only the admin, signed in
// with the password, gives out credentials.
type TokenHandlers struct{ db *sql.DB }

func NewTokenHandlers(db *sql.DB) *TokenHandlers { return &TokenHandlers{db: db} }

func (h *TokenHandlers) Register(r chi.Router, authMW func(http.Handler) http.Handler) {
	r.With(authMW).Get("/api/tokens", h.List)
	r.With(authMW).Post("/api/tokens", h.Create)
	r.With(authMW).Delete("/api/tokens/{id}", h.Revoke)
}

// Token expiry: 90 days unless the request says otherwise; no expiry only
// when it asks for none by name (no_expiry).
const (
	tokenDefaultDays = 90
	tokenMaxDays     = 3650
)

// tokenName is what a token may be called: it shows in the audit log as
// token:<name>, so letters, digits, space, dot, underscore and hyphen.
var tokenName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

// List answers GET /api/tokens: every token, revoked and expired included,
// newest first. The values are not stored, so none is returned.
func (h *TokenHandlers) List(w http.ResponseWriter, r *http.Request) {
	tokens, err := database.ListAPITokens(h.db)
	if err != nil {
		writeInternalError(w, "list API tokens", err)
		return
	}
	writeList(w, tokens, ListMeta{Total: len(tokens), Limit: len(tokens), Offset: 0})
}

// Create answers POST /api/tokens {name, scope, expires_in_days?, no_expiry?}
// with the token and its value, which is shown this once.
func (h *TokenHandlers) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string `json:"name"`
		Scope         string `json:"scope"`
		ExpiresInDays *int   `json:"expires_in_days"`
		NoExpiry      bool   `json:"no_expiry"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if !tokenName.MatchString(req.Name) {
		writeError(w, http.StatusBadRequest, "name: 1 to 64 letters, digits, spaces, dots, underscores or hyphens, starting with a letter or digit")
		return
	}
	if req.Scope != database.ScopeRead && req.Scope != database.ScopeWrite {
		writeError(w, http.StatusBadRequest, "scope: read or write")
		return
	}
	now := time.Now()
	var expiresAt *time.Time
	switch {
	case req.NoExpiry && req.ExpiresInDays != nil:
		writeError(w, http.StatusBadRequest, "give expires_in_days or no_expiry, not both")
		return
	case req.NoExpiry:
	default:
		days := tokenDefaultDays
		if req.ExpiresInDays != nil {
			days = *req.ExpiresInDays
		}
		if days < 1 || days > tokenMaxDays {
			writeError(w, http.StatusBadRequest, "expires_in_days: 1 to 3650")
			return
		}
		t := time.Unix(now.Unix(), 0).UTC().AddDate(0, 0, days)
		expiresAt = &t
	}

	value, token, err := database.CreateAPIToken(h.db, req.Name, req.Scope, requestUser(r), expiresAt, now)
	if errors.Is(err, database.ErrTokenNameTaken) {
		writeError(w, http.StatusConflict, "a token in use has this name; revoke it first or choose another")
		return
	}
	if err != nil {
		writeInternalError(w, "create API token", err)
		return
	}
	expiry := "never"
	if expiresAt != nil {
		expiry = expiresAt.Format(time.RFC3339)
	}
	auditChange(h.db, r, "create_api_token", token.Name, map[string]any{"id": token.ID, "scope": token.Scope, "expires_at": expiry})

	// The value is a credential: no cache keeps the response.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, map[string]any{
		"status":  "success",
		"message": "Copy the token now: it is not shown again.",
		"data": map[string]any{
			"token":      value,
			"id":         token.ID,
			"name":       token.Name,
			"scope":      token.Scope,
			"created_at": token.CreatedAt,
			"expires_at": token.ExpiresAt,
		},
	})
}

// Revoke answers DELETE /api/tokens/{id}: the token stops working at once.
func (h *TokenHandlers) Revoke(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	name, found, err := database.RevokeAPIToken(h.db, id, time.Now())
	if err != nil {
		writeInternalError(w, "revoke API token", err)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "no token in use has this id")
		return
	}
	auditChange(h.db, r, "revoke_api_token", name, map[string]any{"id": id})
	writeJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Token revoked"})
}
