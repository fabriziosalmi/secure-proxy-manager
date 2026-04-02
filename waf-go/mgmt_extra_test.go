package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMgmtHandlers_CategoriesToggleHandler_InvalidJSON(t *testing.T) {
	h := &MgmtHandlers{}

	// Invalid JSON
	r := httptest.NewRequest("POST", "/categories/toggle", bytes.NewReader([]byte("invalid-json")))
	w := httptest.NewRecorder()
	h.CategoriesToggleHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid JSON, got %d", w.Code)
	}

	// GET instead of POST
	r = httptest.NewRequest("GET", "/categories/toggle", nil)
	w = httptest.NewRecorder()
	h.CategoriesToggleHandler(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for GET, got %d", w.Code)
	}
}

func TestMgmtHandlers_ResetHandler_InvalidMethod(t *testing.T) {
	h := &MgmtHandlers{}
	r := httptest.NewRequest("GET", "/reset", nil)
	w := httptest.NewRecorder()
	h.ResetHandler(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for GET on reset, got %d", w.Code)
	}
}
