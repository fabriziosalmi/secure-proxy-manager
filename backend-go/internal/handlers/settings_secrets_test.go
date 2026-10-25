package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appcrypto "github.com/fabriziosalmi/secure-proxy-manager/backend-go/internal/crypto"
)

const testEncKey = "0000000000000000000000000000000000000000000000000000000000000000"

// storeSecret writes a secret the way the settings API does: encrypted.
func storeSecret(t *testing.T, h *SettingsHandlers, key, value string) string {
	t.Helper()
	enc, err := appcrypto.Encrypt(value, h.cfg.EncryptionKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := h.db.Exec("INSERT INTO settings(setting_name,setting_value) VALUES(?,?) ON CONFLICT(setting_name) DO UPDATE SET setting_value=excluded.setting_value", key, enc); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return enc
}

func storedValue(t *testing.T, h *SettingsHandlers, key string) string {
	t.Helper()
	var v string
	_ = h.db.QueryRow("SELECT setting_value FROM settings WHERE setting_name=?", key).Scan(&v)
	return v
}

func bulkUpdate(t *testing.T, h *SettingsHandlers, query string, body map[string]string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	h.BulkUpdate(w, httptest.NewRequest("POST", "/api/settings"+query, bytes.NewReader(raw)))
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w, resp
}

// The data-safety bug: GET returned an unreadable secret as "" with
// decrypt_failed, the UI sent every key back, and BulkUpdate stored the empty
// value, so saving any other setting destroyed the secret. An empty secret in
// a bulk update now keeps the stored value and says so.
func TestBulkUpdateKeepsASecretSentEmpty(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	h := NewSettingsHandlers(db, cfg)
	enc := storeSecret(t, h, "gotify_token", "super-secret-token")

	w, resp := bulkUpdate(t, h, "", map[string]string{"gotify_token": "", "log_retention_days": "14"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := storedValue(t, h, "gotify_token"); got != enc {
		t.Fatalf("the stored secret was overwritten by an empty value: now %q", got)
	}
	if got := storedValue(t, h, "log_retention_days"); got != "14" {
		t.Errorf("the other key in the request was not saved: %q", got)
	}
	data, _ := resp["data"].(map[string]any)
	kept, _ := data["kept"].([]any)
	if len(kept) != 1 || kept[0] != "gotify_token" {
		t.Errorf("the response must name the secret it kept, got %v", data["kept"])
	}
}

// The same holds when the stored secret cannot be decrypted: that is the
// case where the UI used to receive "" and send it back.
func TestBulkUpdateKeepsAnUnreadableSecret(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	h := NewSettingsHandlers(db, cfg)
	enc := storeSecret(t, h, "telegram_bot_token", "123:abc")
	cfg.EncryptionKey = "1111111111111111111111111111111111111111111111111111111111111111" // rotated

	w, _ := bulkUpdate(t, h, "", map[string]string{"telegram_bot_token": ""})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := storedValue(t, h, "telegram_bot_token"); got != enc {
		t.Fatalf("an unreadable secret was wiped by an empty value: now %q", got)
	}
}

// Clearing stays possible, but only when the request names the secret.
func TestBulkUpdateClearsANamedSecret(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	h := NewSettingsHandlers(db, cfg)
	storeSecret(t, h, "webhook_url", "https://hooks.example/abc")
	storeSecret(t, h, "gotify_token", "keep-me")

	w, _ := bulkUpdate(t, h, "?clear=webhook_url", map[string]string{"gotify_token": ""})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := storedValue(t, h, "webhook_url"); got != "" {
		t.Errorf("the named secret was not cleared: %q", got)
	}
	if got := storedValue(t, h, "gotify_token"); got == "" {
		t.Error("a secret that was not named was cleared")
	}
}

func TestBulkUpdateRefusesAnInvalidClear(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	h := NewSettingsHandlers(db, cfg)

	for _, tc := range []struct {
		name, query string
		body        map[string]string
	}{
		{"not a secret", "?clear=proxy_port", map[string]string{}},
		{"cleared and set", "?clear=webhook_url", map[string]string{"webhook_url": "https://x.example"}},
	} {
		w, _ := bulkUpdate(t, h, tc.query, tc.body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", tc.name, w.Code)
		}
	}
}

// A new value still replaces the stored one, encrypted.
func TestBulkUpdateReplacesASecret(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	h := NewSettingsHandlers(db, cfg)
	storeSecret(t, h, "ntfy_topic", "old-topic")

	if w, _ := bulkUpdate(t, h, "", map[string]string{"ntfy_topic": "new-topic"}); w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	dec, err := appcrypto.Decrypt(storedValue(t, h, "ntfy_topic"), cfg.EncryptionKey)
	if err != nil || dec != "new-topic" {
		t.Errorf("expected the new value stored encrypted, got %q (%v)", dec, err)
	}
}

// Secrets are write-only: GET says whether one is stored and whether it can
// be read, never what it is.
func TestGetAllNeverReturnsASecret(t *testing.T) {
	db, _, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	cfg.EncryptionKey = testEncKey
	h := NewSettingsHandlers(db, cfg)
	storeSecret(t, h, "gotify_token", "super-secret-token")
	if _, err := db.Exec("INSERT INTO settings(setting_name,setting_value) VALUES('teams_webhook_url','') ON CONFLICT(setting_name) DO UPDATE SET setting_value=''"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	w := httptest.NewRecorder()
	h.GetAll(w, httptest.NewRequest("GET", "/api/settings", nil))
	if bytes.Contains(w.Body.Bytes(), []byte("super-secret-token")) {
		t.Fatal("GET /api/settings returned a secret in clear")
	}
	var resp struct {
		Data []struct {
			Name          string `json:"setting_name"`
			Value         string `json:"setting_value"`
			Secret        bool   `json:"secret"`
			IsSet         bool   `json:"is_set"`
			DecryptFailed bool   `json:"decrypt_failed"`
		} `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	seen := map[string]bool{}
	for _, row := range resp.Data {
		switch row.Name {
		case "gotify_token":
			seen[row.Name] = true
			if !row.Secret || !row.IsSet || row.DecryptFailed || row.Value != "" {
				t.Errorf("gotify_token: want secret, set, readable, no value; got %+v", row)
			}
		case "teams_webhook_url":
			seen[row.Name] = true
			if !row.Secret || row.IsSet {
				t.Errorf("teams_webhook_url: want secret and not set; got %+v", row)
			}
		case "proxy_port":
			seen[row.Name] = true
			if row.Secret || row.Value != "3128" {
				t.Errorf("proxy_port is not a secret and keeps its value; got %+v", row)
			}
		}
	}
	if len(seen) != 3 {
		t.Fatalf("rows missing from the response: saw %v", seen)
	}
}
