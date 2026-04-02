package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHandlers_Score_Variations(t *testing.T) {
	db, svc, cfg, cleanup := setupTestDB(t)
	defer cleanup()
	h := NewSecurityHandlers(db, svc, cfg, nil)

	// All OFF (Note: default_password_changed might be true from setupTestDB depending on logic)
	db.Exec("UPDATE settings SET setting_value='false' WHERE setting_name IN ('enable_ip_blacklist', 'enable_domain_blacklist', 'block_direct_ip', 'enable_content_filtering', 'enable_waf', 'ssl_bump_enabled', 'default_password_changed', 'enable_time_restrictions')")
	
	r := httptest.NewRequest("GET", "/api/security/score", nil)
	w := httptest.NewRecorder()
	h.Score(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp struct {
		Data struct {
			Score float64 `json:"score"`
		} `json:"data"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	// Base points are usually 0 if all are false
	if resp.Data.Score > 5 {
		t.Errorf("Expected very low score for all OFF, got %f", resp.Data.Score)
	}

	// All ON
	db.Exec("UPDATE settings SET setting_value='true' WHERE setting_name IN ('enable_ip_blacklist', 'enable_domain_blacklist', 'block_direct_ip', 'enable_content_filtering', 'enable_waf', 'ssl_bump_enabled', 'default_password_changed', 'enable_time_restrictions')")
	
	w = httptest.NewRecorder()
	h.Score(w, r)
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Data.Score < 95 { // Should be 100
		t.Errorf("Expected high score for all ON, got %f", resp.Data.Score)
	}
}
