package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"golang.org/x/oauth2"

	"github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/auth"
)

// Sign-in with an OpenID Connect provider: authorization code with PKCE
// (decision record in issue #592). GET /api/auth/oidc/login sends the browser
// to the provider with a fresh state, nonce and PKCE challenge, kept for ten
// minutes in a signed, HttpOnly cookie; GET /api/auth/oidc/callback checks
// the state against that cookie, exchanges the code with the verifier, checks
// the ID token (signature from the provider's keys, issuer, audience, expiry)
// and its nonce, and lets the person in only when OIDC_ALLOWED_EMAILS or
// OIDC_ALLOWED_GROUPS names them. The session is the dashboard's cookie, for
// the user oidc:<email>, lasting OIDC_SESSION_DURATION.

// oidcFlowCookie carries the sign-in in progress between login and callback.
// SameSite=Lax, not Strict: the callback is a navigation from the provider's
// site, which a Strict cookie would not be sent with.
const (
	oidcFlowCookie = "spm_oidc_flow"
	oidcFlowTTL    = 10 * time.Minute
)

type oidcFlow struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
}

// oidcClient holds the provider, read once from its discovery document.
type oidcClient struct {
	mu       sync.Mutex
	provider *oidc.Provider
	http     *http.Client // nil: http.DefaultClient
}

// WithOIDCHTTPClient sets the client the backend reaches the provider with
// (tests give the mock provider's).
func (h *AuthHandlers) WithOIDCHTTPClient(c *http.Client) *AuthHandlers {
	h.oidc.http = c
	return h
}

func (h *AuthHandlers) oidcContext(ctx context.Context) context.Context {
	if h.oidc.http != nil {
		return oidc.ClientContext(ctx, h.oidc.http)
	}
	return ctx
}

// oidcProvider reads the discovery document the first time it is needed and
// keeps it; a provider that cannot be reached is asked again next time.
func (h *AuthHandlers) oidcProvider(ctx context.Context) (*oidc.Provider, error) {
	h.oidc.mu.Lock()
	defer h.oidc.mu.Unlock()
	if h.oidc.provider != nil {
		return h.oidc.provider, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(h.oidcContext(ctx), h.cfg.OIDC.Issuer)
	if err != nil {
		return nil, err
	}
	h.oidc.provider = p
	return p, nil
}

func (h *AuthHandlers) oauthConfig(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     h.cfg.OIDC.ClientID,
		ClientSecret: h.cfg.OIDC.ClientSecret,
		RedirectURL:  h.cfg.OIDC.RedirectURL,
		Endpoint:     p.Endpoint(),
		Scopes:       h.cfg.OIDC.Scopes,
	}
}

func (h *AuthHandlers) registerOIDC(r chi.Router) {
	r.Get("/api/auth/oidc", h.OIDCStatus)
	r.Get("/api/auth/oidc/login", h.OIDCLogin)
	r.Get("/api/auth/oidc/callback", h.OIDCCallback)
}

// OIDCStatus tells the sign-in page whether to offer the provider.
func (h *AuthHandlers) OIDCStatus(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{"enabled": h.cfg.OIDC.Enabled()}
	if h.cfg.OIDC.Enabled() {
		data["label"] = h.cfg.OIDC.Label
		// The sign-in page hides the password form when it would be refused.
		data["password_login"] = !h.svc.PasswordOff(r)
	}
	writeOK(w, data)
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// flowMAC signs the flow cookie with a key of its own, derived from SECRET_KEY.
func (h *AuthHandlers) flowMAC(payload string) string {
	k := hmac.New(sha256.New, []byte(h.cfg.SecretKey))
	k.Write([]byte("spm-oidc-flow"))
	m := hmac.New(sha256.New, k.Sum(nil))
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (h *AuthHandlers) setFlowCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcFlowCookie,
		Value:    value,
		Path:     "/api/auth/oidc",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// readFlow returns the sign-in the cookie carries, if it is ours and fresh.
func (h *AuthHandlers) readFlow(r *http.Request) (oidcFlow, bool) {
	c, err := r.Cookie(oidcFlowCookie)
	if err != nil {
		return oidcFlow{}, false
	}
	payload, mac, ok := strings.Cut(c.Value, ".")
	if !ok || subtle.ConstantTimeCompare([]byte(mac), []byte(h.flowMAC(payload))) != 1 {
		return oidcFlow{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return oidcFlow{}, false
	}
	var f oidcFlow
	if json.Unmarshal(raw, &f) != nil || f.State == "" || f.Nonce == "" || f.Verifier == "" || time.Now().Unix() > f.Expires {
		return oidcFlow{}, false
	}
	return f, true
}

// OIDCLogin sends the browser to the provider.
func (h *AuthHandlers) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.OIDC.Enabled() {
		writeError(w, http.StatusNotFound, "OIDC sign-in is not configured")
		return
	}
	p, err := h.oidcProvider(r.Context())
	if err != nil {
		writeInternalError(w, "oidc discovery", err)
		return
	}
	f := oidcFlow{State: randomToken(), Nonce: randomToken(), Verifier: oauth2.GenerateVerifier(), Expires: time.Now().Add(oidcFlowTTL).Unix()}
	raw, _ := json.Marshal(f)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	h.setFlowCookie(w, r, payload+"."+h.flowMAC(payload), int(oidcFlowTTL.Seconds()))
	url := h.oauthConfig(p).AuthCodeURL(f.State, oidc.Nonce(f.Nonce), oauth2.S256ChallengeOption(f.Verifier))
	http.Redirect(w, r, url, http.StatusFound)
}

// oidcIdentity is what SPM reads from the ID token.
type oidcIdentity struct {
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified"`
}

// groupsOf reads the groups claim, a list of strings or a single string.
func groupsOf(claims map[string]any, name string) []string {
	switch v := claims[name].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, g := range v {
			if s, ok := g.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// oidcAllowed reports whether the configuration lets this person in.
func (h *AuthHandlers) oidcAllowed(email string, groups []string) bool {
	if slices.Contains(h.cfg.OIDC.AllowedEmails, email) {
		return true
	}
	for _, g := range groups {
		if slices.Contains(h.cfg.OIDC.AllowedGroups, g) {
			return true
		}
	}
	return false
}

// oidcFail ends a sign-in that did not succeed: audited, and the browser is
// sent to the dashboard with a reason it can show (?oidc_error=).
func (h *AuthHandlers) oidcFail(w http.ResponseWriter, r *http.Request, user, reason string, err error) {
	detail := reason
	if err != nil {
		detail += ": " + err.Error()
	}
	if user == "" {
		user = "oidc"
	}
	h.store.Audit(user, "login_failed", auth.ClientIP(r), auditJSON(map[string]any{"via": "oidc", "reason": detail}))
	http.Redirect(w, r, "/?oidc_error="+reason, http.StatusFound)
}

// OIDCCallback finishes the sign-in the provider sends the browser back from.
func (h *AuthHandlers) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !h.cfg.OIDC.Enabled() {
		writeError(w, http.StatusNotFound, "OIDC sign-in is not configured")
		return
	}
	f, ok := h.readFlow(r)
	// The flow is used once, whatever happens next.
	h.setFlowCookie(w, r, "", -1)
	q := r.URL.Query()
	if !ok || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(f.State)) != 1 {
		h.oidcFail(w, r, "", "state", nil)
		return
	}
	if e := q.Get("error"); e != "" {
		h.oidcFail(w, r, "", "provider", errors.New(e))
		return
	}
	p, err := h.oidcProvider(r.Context())
	if err != nil {
		h.oidcFail(w, r, "", "unavailable", err)
		return
	}
	ctx, cancel := context.WithTimeout(h.oidcContext(r.Context()), 15*time.Second)
	defer cancel()
	tok, err := h.oauthConfig(p).Exchange(ctx, q.Get("code"), oauth2.VerifierOption(f.Verifier))
	if err != nil {
		h.oidcFail(w, r, "", "exchange", err)
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		h.oidcFail(w, r, "", "token", errors.New("no id_token in the answer"))
		return
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: h.cfg.OIDC.ClientID}).Verify(ctx, rawID)
	if err != nil {
		h.oidcFail(w, r, "", "token", err)
		return
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(f.Nonce)) != 1 {
		h.oidcFail(w, r, "", "token", errors.New("nonce mismatch"))
		return
	}
	var id oidcIdentity
	var all map[string]any
	if err := idt.Claims(&id); err != nil || idt.Claims(&all) != nil {
		h.oidcFail(w, r, "", "token", err)
		return
	}
	email := strings.ToLower(strings.TrimSpace(id.Email))
	if email == "" {
		h.oidcFail(w, r, "", "no_email", nil)
		return
	}
	user := auth.OIDCUserPrefix + email
	if id.EmailVerified != nil && !*id.EmailVerified {
		h.oidcFail(w, r, user, "unverified_email", nil)
		return
	}
	if !h.oidcAllowed(email, groupsOf(all, h.cfg.OIDC.GroupsClaim)) {
		h.oidcFail(w, r, user, "not_allowed", nil)
		return
	}
	session, exp, err := h.svc.IssueOIDCSession(email)
	if err != nil {
		h.oidcFail(w, r, user, "session", err)
		return
	}
	setSessionCookie(w, r, session, exp)
	h.store.Audit(user, "login", auth.ClientIP(r), auditJSON(map[string]any{"via": "oidc"}))
	http.Redirect(w, r, "/", http.StatusFound)
}

// oidcLogoutURL is where to send the browser to end its session at the
// provider too (RP-initiated logout), when the provider advertises an
// end_session_endpoint; "" otherwise. It comes back to the dashboard.
func (h *AuthHandlers) oidcLogoutURL(ctx context.Context) string {
	if !h.cfg.OIDC.Enabled() {
		return ""
	}
	p, err := h.oidcProvider(ctx)
	if err != nil {
		return ""
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	if p.Claims(&meta) != nil || meta.EndSession == "" {
		return ""
	}
	end, err := url.Parse(meta.EndSession)
	back, err2 := url.Parse(h.cfg.OIDC.RedirectURL)
	if err != nil || err2 != nil || (end.Scheme != "https" && end.Scheme != "http") {
		return ""
	}
	q := end.Query()
	q.Set("client_id", h.cfg.OIDC.ClientID)
	q.Set("post_logout_redirect_uri", back.Scheme+"://"+back.Host+"/")
	end.RawQuery = q.Encode()
	return end.String()
}
