package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func testKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := testKey()
	tests := []string{
		"https://hooks.slack.com/services/T00000000/B00000000/XXXX",
		"my-gotify-token-abc123",
		"",
		"short",
		"a very long string that is repeated many times " +
			"a very long string that is repeated many times " +
			"a very long string that is repeated many times",
	}
	for _, plain := range tests {
		enc, err := Encrypt(plain, key)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", plain, err)
		}
		if plain == "" && enc != "" {
			t.Fatal("empty plaintext should return empty string")
		}
		dec, err := Decrypt(enc, key)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if dec != plain {
			t.Fatalf("roundtrip failed: got %q, want %q", dec, plain)
		}
	}
}

func TestDecryptPlaintextPassthrough(t *testing.T) {
	key := testKey()
	plain := "https://example.com/webhook"
	dec, err := Decrypt(plain, key)
	if err != nil {
		t.Fatal(err)
	}
	if dec != plain {
		t.Fatalf("passthrough failed: got %q, want %q", dec, plain)
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key1 := testKey()
	key2 := testKey()
	enc, _ := Encrypt("secret", key1)
	_, err := Decrypt(enc, key2)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestIsSensitive(t *testing.T) {
	if !IsSensitive("gotify_token") {
		t.Fatal("gotify_token should be sensitive")
	}
	if IsSensitive("proxy_port") {
		t.Fatal("proxy_port should not be sensitive")
	}
}
