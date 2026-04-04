// Package crypto provides AES-256-GCM encryption for sensitive settings stored in the database.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

// SensitiveKeys lists setting names that should be encrypted at rest.
var SensitiveKeys = map[string]struct{}{
	"webhook_url":        {},
	"gotify_url":         {},
	"gotify_token":       {},
	"teams_webhook_url":  {},
	"telegram_bot_token": {},
	"telegram_chat_id":   {},
	"ntfy_url":           {},
	"ntfy_topic":         {},
}

// IsSensitive returns true if the setting key should be encrypted.
func IsSensitive(key string) bool {
	_, ok := SensitiveKeys[key]
	return ok
}

const encPrefix = "enc::"

// Encrypt encrypts plaintext using AES-256-GCM with the given hex-encoded key.
// Returns "enc::<hex nonce><hex ciphertext>".
func Encrypt(plaintext, hexKey string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != 32 {
		return "", errors.New("encryption key must be 32 bytes (64 hex chars)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)
	return encPrefix + hex.EncodeToString(nonce) + hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a value previously encrypted with Encrypt.
// If the value is not encrypted (no "enc::" prefix), it is returned as-is.
func Decrypt(stored, hexKey string) (string, error) {
	if !strings.HasPrefix(stored, encPrefix) {
		return stored, nil // plaintext passthrough for migration
	}
	data := stored[len(encPrefix):]
	key, err := hex.DecodeString(hexKey)
	if err != nil || len(key) != 32 {
		return "", errors.New("encryption key must be 32 bytes (64 hex chars)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	// data is hex(nonce) + hex(ciphertext)
	nonceHexLen := nonceSize * 2
	if len(data) < nonceHexLen {
		return "", errors.New("ciphertext too short")
	}
	nonce, err := hex.DecodeString(data[:nonceHexLen])
	if err != nil {
		return "", err
	}
	ciphertext, err := hex.DecodeString(data[nonceHexLen:])
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
