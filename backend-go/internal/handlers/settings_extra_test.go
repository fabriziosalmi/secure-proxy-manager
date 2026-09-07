package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestSettingsHandlers_Register(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)
	r := chi.NewRouter()
	authMW := func(next http.Handler) http.Handler { return next }
	h.Register(r, authMW)
}

func TestSettingsHandlers_Update_TooLong(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	val := make([]byte, 10001)
	for i := range val {
		val[i] = 'a'
	}
	body, _ := json.Marshal(map[string]string{"value": string(val)})

	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", "test")
	r := httptest.NewRequest("PUT", "/api/settings/test", bytes.NewBuffer(body))
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.Update(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for too long value, got %d", w.Code)
	}
}

func TestSettingsHandlers_Update_InvalidJSON(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	r := httptest.NewRequest("PUT", "/api/settings/test", bytes.NewBufferString("invalid json"))
	w := httptest.NewRecorder()
	h.Update(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestSettingsHandlers_BulkUpdate_SSLBump(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	// Test Enable SSL Bump
	body, _ := json.Marshal(map[string]string{"ssl_bump_enabled": "true"})
	r := httptest.NewRequest("POST", "/api/settings", bytes.NewBuffer(body))
	w := httptest.NewRecorder()
	h.BulkUpdate(w, r)

	toggleFile := filepath.Join(cfg.ConfigDir, "ssl_bump_enabled")
	if _, err := os.Stat(toggleFile); os.IsNotExist(err) {
		t.Error("Expected ssl_bump_enabled file to exist")
	}

	// Test Disable SSL Bump
	body, _ = json.Marshal(map[string]string{"ssl_bump_enabled": "false"})
	r = httptest.NewRequest("POST", "/api/settings", bytes.NewBuffer(body))
	w = httptest.NewRecorder()
	h.BulkUpdate(w, r)

	if _, err := os.Stat(toggleFile); !os.IsNotExist(err) {
		t.Error("Expected ssl_bump_enabled file to be deleted")
	}
}

func TestSettingsHandlers_BulkUpdate_InvalidJSON(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSettingsHandlers(db, cfg)

	r := httptest.NewRequest("POST", "/api/settings", bytes.NewBufferString("invalid json"))
	w := httptest.NewRecorder()
	h.BulkUpdate(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid JSON, got %d", w.Code)
	}
}

// SECURE-ERR-04: a sensitive setting whose encryption fails must be refused,
// not written in cleartext with a 200. The trigger is the realistic one — an
// EncryptionKey that is not 32 bytes of hex, i.e. a misconfigured deployment.
func TestSettingsHandlers_Update_RefusesPlaintextOnEncryptFailure(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = "not-a-valid-hex-key"
	h := NewSettingsHandlers(db, cfg)

	const secret = "https://hooks.example/T00000/B00000/XXXXXXXXXXXX"
	body, _ := json.Marshal(map[string]string{"value": secret})
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", "webhook_url") // in crypto.SensitiveKeys
	r := httptest.NewRequest("PUT", "/api/settings/webhook_url", bytes.NewBuffer(body))
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.Update(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when encryption is unavailable, got %d: %s", w.Code, w.Body.String())
	}

	// The decisive assertion: the secret must not be on disk in cleartext.
	var stored string
	_ = db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='webhook_url'").Scan(&stored)
	if stored == secret {
		t.Error("sensitive setting was stored in PLAINTEXT after the encryption failure")
	}
}

// SECURE-ERR-06: a sensitive value that cannot be decrypted must come back
// empty and flagged, never as the raw enc:: ciphertext — returning the blob
// puts it in the form field, and the next Save re-encrypts it as if it were
// the plaintext, destroying the secret irrecoverably.
func TestSettingsHandlers_GetAll_DoesNotLeakCiphertextOnDecryptFailure(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()

	// Store a value encrypted under one key, then read it back under another.
	cfg.EncryptionKey = "0000000000000000000000000000000000000000000000000000000000000000"
	h := NewSettingsHandlers(db, cfg)
	body, _ := json.Marshal(map[string]string{"value": "super-secret-token"})
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("name", "gotify_token")
	r := httptest.NewRequest("PUT", "/api/settings/gotify_token", bytes.NewBuffer(body))
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Update(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("setup write failed: %d %s", w.Code, w.Body.String())
	}

	var raw string
	if err := db.QueryRow("SELECT setting_value FROM settings WHERE setting_name='gotify_token'").Scan(&raw); err != nil {
		t.Fatalf("read back: %v", err)
	}

	cfg.EncryptionKey = "1111111111111111111111111111111111111111111111111111111111111111" // rotated
	h2 := NewSettingsHandlers(db, cfg)
	w2 := httptest.NewRecorder()
	h2.GetAll(w2, httptest.NewRequest("GET", "/api/settings", nil))

	var resp struct {
		Data []struct {
			Name          string `json:"setting_name"`
			Value         string `json:"setting_value"`
			DecryptFailed bool   `json:"decrypt_failed"`
		} `json:"data"`
	}
	if err := json.NewDecoder(w2.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, row := range resp.Data {
		if row.Name != "gotify_token" {
			continue
		}
		found = true
		if row.Value == raw {
			t.Error("GetAll returned the raw ciphertext — a Save would re-encrypt it and destroy the secret")
		}
		if row.Value != "" {
			t.Errorf("expected an empty value for an undecryptable setting, got %q", row.Value)
		}
		if !row.DecryptFailed {
			t.Error("decrypt_failed was not set, so the UI cannot tell the value is unreadable")
		}
	}
	if !found {
		t.Fatal("gotify_token missing from the response")
	}
}
