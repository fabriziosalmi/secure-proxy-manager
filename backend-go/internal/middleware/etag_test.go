package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestETagConditionalGet(t *testing.T) {
	h := ETag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
	}))

	// First GET: 200 with a strong ETag and the body intact.
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec1.Code != http.StatusOK {
		t.Fatalf("first GET: want 200, got %d", rec1.Code)
	}
	etag := rec1.Header().Get("ETag")
	if etag == "" {
		t.Fatal("expected ETag header on first response")
	}
	if rec1.Header().Get("Content-Type") != "application/json" {
		t.Errorf("handler Content-Type not preserved: %q", rec1.Header().Get("Content-Type"))
	}
	if rec1.Body.String() != `{"ok":true}` {
		t.Errorf("unexpected body: %q", rec1.Body.String())
	}

	// Matching If-None-Match: 304 with no body.
	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req2.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("matching INM: want 304, got %d", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Errorf("304 must have empty body, got %q", rec2.Body.String())
	}

	// Stale If-None-Match: full 200 again.
	req3 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req3.Header.Set("If-None-Match", `"deadbeef"`)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("stale INM: want 200, got %d", rec3.Code)
	}
}

func TestETagBypassesNonGet(t *testing.T) {
	h := ETag(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("made")) //nolint:errcheck
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST should pass through: want 201, got %d", rec.Code)
	}
	if rec.Header().Get("ETag") != "" {
		t.Error("non-GET must not get an ETag")
	}
}

func TestETagMatches(t *testing.T) {
	cases := []struct {
		header, etag string
		want         bool
	}{
		{"", `"a"`, false},
		{"*", `"a"`, true},
		{`"a"`, `"a"`, true},
		{`W/"a"`, `"a"`, true},
		{`"x", "a", "y"`, `"a"`, true},
		{`"x"`, `"a"`, false},
	}
	for _, c := range cases {
		if got := etagMatches(c.header, c.etag); got != c.want {
			t.Errorf("etagMatches(%q,%q)=%v want %v", c.header, c.etag, got, c.want)
		}
	}
}
