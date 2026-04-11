package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDNSDetectHandlers_Detect(t *testing.T) {
	db, _, _, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewDNSDetectHandlers(db)

	// Test with subnet provided
	body, _ := json.Marshal(map[string]string{"subnet": "127.0.0"})
	r := httptest.NewRequest("POST", "/api/dns/detect", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Detect(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	var resp struct {
		Data map[string]any `json:"data"`
	}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Data["subnet"] != "127.0.0" {
		t.Errorf("Expected subnet 127.0.0, got %v", resp.Data["subnet"])
	}

	// Test auto-detect (might return 400 in CI if no external IP)
	r = httptest.NewRequest("POST", "/api/dns/detect", bytes.NewReader([]byte("{}")))
	w = httptest.NewRecorder()
	h.Detect(w, r)
	// We don't assert 200 here because it depends on host network
}
