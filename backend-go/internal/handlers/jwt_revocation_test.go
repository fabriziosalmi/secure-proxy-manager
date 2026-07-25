package handlers

// Regression test for GHSA-j5fj-8wxc-gvmj — "Logout Bypass via Alternate JWT
// Spelling" (CWE-613 Insufficient Session Expiration).
//
// The revocation blacklist is keyed by SHA-256 of the compact JWT string, but
// golang-jwt decodes Base64URL non-strictly by default: a token whose final
// signature character is swapped for an equivalent spelling (only unused bits
// differ) decodes to the same signature bytes, so it still validates — yet
// hashes to a different blacklist key. Before the fix, such an "equivalent
// spelling" was accepted AFTER the original had been revoked at logout,
// defeating token revocation. The fix pins jwt.WithStrictDecoding() at every
// parse site so only the canonical spelling parses.
//
// Reported under coordinated disclosure by a UC Berkeley security research
// project: Corban Villa (@corbanvilla), Sohee Kim (@soh3e), and Austin Chu
// (@dderpym). This test is adapted from the proof-of-concept in their advisory,
// with the post-fix expectation: the equivalent spelling must now be rejected.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// equivalentJWT returns a distinct compact spelling of token that decodes to
// the same signature bytes (a non-canonical Base64URL spelling of the final
// character). It fails the test if no such alias exists for this signature.
func equivalentJWT(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, character := range alphabet {
		alias := parts[2][:len(parts[2])-1] + string(character)
		decoded, err := base64.RawURLEncoding.DecodeString(alias)
		if alias != parts[2] && err == nil && bytes.Equal(decoded, signature) {
			return strings.Join([]string{parts[0], parts[1], alias}, ".")
		}
	}
	t.Fatal("no equivalent signature spelling")
	return ""
}

func TestJWTRevocationBypassThroughHTTP(t *testing.T) {
	db, service, cfg, cleanup := setupTestDB(t)
	defer cleanup()

	router := chi.NewRouter()
	NewAuthHandlers(db, service, cfg, nil, nil).Register(router)
	server := httptest.NewServer(router)
	defer server.Close()

	request := func(method, path, token, body string) int {
		req, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		io.Copy(io.Discard, response.Body)
		return response.StatusCode
	}

	login, err := http.Post(
		server.URL+"/api/auth/login",
		"application/json",
		strings.NewReader(`{"username":"admin","password":"admin-12345"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer login.Body.Close()
	var tokens map[string]string
	if err := json.NewDecoder(login.Body).Decode(&tokens); err != nil {
		t.Fatal(err)
	}
	original := tokens["access_token"]
	if original == "" {
		t.Fatal("login did not return an access_token")
	}
	alternate := equivalentJWT(t, original)

	// A token whose signature bytes differ (first char changed) must always be
	// rejected — this guards the equivalentJWT helper against silently testing a
	// still-valid signature.
	parts := strings.Split(original, ".")
	replacement := "A"
	if parts[2][0] == 'A' {
		replacement = "B"
	}
	tampered := strings.Join(
		[]string{parts[0], parts[1], replacement + parts[2][1:]},
		".",
	)

	checks := []struct {
		label, method, path, token string
		want                       int
	}{
		{"baseline", "GET", "/api/ws-token", original, http.StatusOK},
		{"logout", "POST", "/api/logout", original, http.StatusOK},
		{"revoked original", "GET", "/api/ws-token", original, http.StatusUnauthorized},
		// Pre-fix this returned 200 (the bypass). WithStrictDecoding() makes the
		// non-canonical spelling fail to parse, so it is now rejected as invalid.
		{"equivalent spelling", "GET", "/api/ws-token", alternate, http.StatusUnauthorized},
		{"tampered signature", "GET", "/api/ws-token", tampered, http.StatusUnauthorized},
	}
	for _, check := range checks {
		got := request(check.method, check.path, check.token, "")
		t.Logf("%s: %d", check.label, got)
		if got != check.want {
			t.Fatalf("%s: got %d, want %d", check.label, got, check.want)
		}
	}
}
