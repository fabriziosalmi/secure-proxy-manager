package database

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

var tokenValue = regexp.MustCompile(`^spm_[0-9a-f]{12}_[A-Za-z0-9_-]{43}$`)

func otherChar(c byte) string {
	if c == 'A' {
		return "B"
	}
	return "A"
}

func TestAnAPITokenIsCheckedAndOnlyItsHashIsKept(t *testing.T) {
	db := openInit(t)
	now := time.Unix(1_800_000_000, 0)
	exp := now.Add(48 * time.Hour)
	value, tok, err := CreateAPIToken(db, "ci", ScopeRead, "admin", &exp, now)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !tokenValue.MatchString(value) {
		t.Fatalf("value %q is not spm_<id>_<secret>", value)
	}
	secret := value[len("spm_")+len(tok.ID)+1:] // base64url: the secret may hold "_" itself
	// The secret is not in any column of the row.
	var row string
	if err := db.QueryRow(`SELECT id||name||scope||secret_sha256||created_by||created_at||expires_at FROM api_tokens`).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row, secret) {
		t.Fatal("the secret is stored")
	}

	got, ok, err := CheckAPIToken(db, value, now)
	if err != nil || !ok || got.ID != tok.ID || got.Scope != ScopeRead || got.Name != "ci" {
		t.Fatalf("check of the value: %+v ok=%v err=%v", got, ok, err)
	}
	for name, v := range map[string]string{
		"wrong secret": value[:len(value)-1] + otherChar(value[len(value)-1]),
		"other id":     "spm_000000000000_" + secret,
		"no prefix":    strings.TrimPrefix(value, "spm_"),
		"no secret":    "spm_" + tok.ID + "_",
		"no separator": "spm_" + tok.ID,
	} {
		if _, ok, err := CheckAPIToken(db, v, now); ok || err != nil {
			t.Errorf("%s: accepted=%v err=%v", name, ok, err)
		}
	}
	if _, ok, _ := CheckAPIToken(db, value, exp.Add(-time.Second)); !ok {
		t.Error("refused a second before it expires")
	}
	if _, ok, _ := CheckAPIToken(db, value, exp); ok {
		t.Error("accepted when it expires")
	}

	name, found, err := RevokeAPIToken(db, tok.ID, now)
	if err != nil || !found || name != "ci" {
		t.Fatalf("revoke: %q %v %v", name, found, err)
	}
	if _, ok, _ := CheckAPIToken(db, value, now); ok {
		t.Error("a revoked token is accepted")
	}
	if _, found, _ := RevokeAPIToken(db, tok.ID, now); found {
		t.Error("revoked twice")
	}
}

func TestATokenNameIsUniqueAmongTokensInUse(t *testing.T) {
	db := openInit(t)
	now := time.Now()
	_, first, err := CreateAPIToken(db, "mcp", ScopeRead, "admin", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := CreateAPIToken(db, "mcp", ScopeWrite, "admin", nil, now); !errors.Is(err, ErrTokenNameTaken) {
		t.Fatalf("second active token with the same name: %v", err)
	}
	if _, _, err := RevokeAPIToken(db, first.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CreateAPIToken(db, "mcp", ScopeWrite, "admin", nil, now); err != nil {
		t.Fatalf("the name of a revoked token cannot be reused: %v", err)
	}
	list, err := ListAPITokens(db)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %d %v", len(list), err)
	}
}

func TestATokenRecordsItsUseAtMostOnceAMinute(t *testing.T) {
	db := openInit(t)
	now := time.Unix(1_800_000_000, 0)
	_, tok, _ := CreateAPIToken(db, "x", ScopeRead, "admin", nil, now)
	used := func() int64 {
		var v int64
		db.QueryRow(`SELECT last_used_at FROM api_tokens WHERE id = ?`, tok.ID).Scan(&v) //nolint:errcheck
		return v
	}
	TouchAPIToken(db, tok.ID, now)
	TouchAPIToken(db, tok.ID, now.Add(30*time.Second))
	if used() != now.Unix() {
		t.Errorf("last_used_at %d, want %d (a use within the minute writes nothing)", used(), now.Unix())
	}
	TouchAPIToken(db, tok.ID, now.Add(61*time.Second))
	if used() != now.Add(61*time.Second).Unix() {
		t.Errorf("last_used_at %d after a minute", used())
	}
}
