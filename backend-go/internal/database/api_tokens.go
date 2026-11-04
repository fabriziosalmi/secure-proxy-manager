package database

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// APIToken is a credential for scripts and tools: a name, a scope ("read"
// or "write") and an optional expiry. Its value, spm_<id>_<secret>, is shown
// once when it is created; only the SHA-256 of the secret is stored. The
// secret is 256 random bits, so a fast hash is enough: there is no password
// to guess.
type APIToken struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Scope      string     `json:"scope"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

// Token scopes.
const (
	ScopeRead  = "read"
	ScopeWrite = "write"
)

// APITokenPrefix starts every token value.
const APITokenPrefix = "spm_"

// ErrTokenNameTaken is CreateAPIToken refusing a name already in use.
var ErrTokenNameTaken = errors.New("a token with this name exists")

func randomPart(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func secretHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// CreateAPIToken stores a token and returns its value, which is not kept.
func CreateAPIToken(db *sql.DB, name, scope, createdBy string, expiresAt *time.Time, now time.Time) (string, APIToken, error) {
	idBytes := make([]byte, 6)
	if _, err := rand.Read(idBytes); err != nil {
		return "", APIToken{}, err
	}
	id := hex.EncodeToString(idBytes)
	secret, err := randomPart(32)
	if err != nil {
		return "", APIToken{}, err
	}
	var exp any
	if expiresAt != nil {
		exp = expiresAt.Unix()
	}
	_, err = db.Exec(`INSERT INTO api_tokens (id, name, scope, secret_sha256, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, id, name, scope, secretHash(secret), createdBy, now.Unix(), exp)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return "", APIToken{}, ErrTokenNameTaken
		}
		return "", APIToken{}, err
	}
	t := APIToken{ID: id, Name: name, Scope: scope, CreatedBy: createdBy, CreatedAt: time.Unix(now.Unix(), 0).UTC(), ExpiresAt: expiresAt}
	return APITokenPrefix + id + "_" + secret, t, nil
}

func unixPtr(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(v.Int64, 0).UTC()
	return &t
}

// ListAPITokens is every token, the newest first, revoked ones included.
func ListAPITokens(db *sql.DB) ([]APIToken, error) {
	rows, err := db.Query(`SELECT id, name, scope, created_by, created_at, expires_at, last_used_at, revoked_at
		FROM api_tokens ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		var t APIToken
		var created int64
		var exp, used, revoked sql.NullInt64
		if err := rows.Scan(&t.ID, &t.Name, &t.Scope, &t.CreatedBy, &created, &exp, &used, &revoked); err != nil {
			return nil, err
		}
		t.CreatedAt = time.Unix(created, 0).UTC()
		t.ExpiresAt, t.LastUsedAt, t.RevokedAt = unixPtr(exp), unixPtr(used), unixPtr(revoked)
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken revokes token id and returns its name; found is false when
// there is no such token or it was already revoked.
func RevokeAPIToken(db *sql.DB, id string, now time.Time) (name string, found bool, err error) {
	err = db.QueryRow(`UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL RETURNING name`,
		now.Unix(), id).Scan(&name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return name, true, nil
}

// CheckAPIToken checks a token value: it names a token, its secret matches,
// and it is neither revoked nor expired at now. ok is false otherwise, with
// no distinction, so the answer tells a guesser nothing.
func CheckAPIToken(db *sql.DB, value string, now time.Time) (t APIToken, ok bool, err error) {
	rest, found := strings.CutPrefix(value, APITokenPrefix)
	if !found {
		return t, false, nil
	}
	id, secret, found := strings.Cut(rest, "_")
	if !found || id == "" || secret == "" {
		return t, false, nil
	}
	var hash string
	var created int64
	var exp, used, revoked sql.NullInt64
	err = db.QueryRow(`SELECT id, name, scope, created_by, created_at, expires_at, last_used_at, revoked_at, secret_sha256
		FROM api_tokens WHERE id = ?`, id).Scan(&t.ID, &t.Name, &t.Scope, &t.CreatedBy, &created, &exp, &used, &revoked, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return APIToken{}, false, nil
	}
	if err != nil {
		return APIToken{}, false, err
	}
	if subtle.ConstantTimeCompare([]byte(secretHash(secret)), []byte(hash)) != 1 || revoked.Valid ||
		(exp.Valid && now.Unix() >= exp.Int64) {
		return APIToken{}, false, nil
	}
	t.CreatedAt = time.Unix(created, 0).UTC()
	t.ExpiresAt, t.LastUsedAt = unixPtr(exp), unixPtr(used)
	return t, true, nil
}

// TouchAPIToken records that token id was used at now, at most once a
// minute, so a busy script does not write on every request.
func TouchAPIToken(db *sql.DB, id string, now time.Time) {
	db.Exec(`UPDATE api_tokens SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at <= ?)`, //nolint:errcheck
		now.Unix(), id, now.Add(-time.Minute).Unix())
}
