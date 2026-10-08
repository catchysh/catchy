// Package seal encrypts secrets stored in the database, such as guard
// secrets, with a key from the ENCRYPTION_KEY environment variable.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// prefix marks the format of a sealed value, so it can change later.
const prefix = "v1:"

// Sealer encrypts and decrypts secrets with AES-256-GCM.
type Sealer struct {
	aead cipher.AEAD
}

// New derives a 256-bit key from key (any non-empty string; e.g. the output
// of `openssl rand -base64 32`).
func New(key string) (*Sealer, error) {
	if key == "" {
		return nil, errors.New("seal: empty key")
	}
	sum := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// Seal encrypts plaintext into a printable string.
func (s *Sealer) Seal(plaintext string) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}
	sealed := s.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return prefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Open decrypts a value from Seal. It fails if the value was sealed with a
// different key or has been tampered with.
func (s *Sealer) Open(sealed string) (string, error) {
	enc, ok := strings.CutPrefix(sealed, prefix)
	if !ok {
		return "", errors.New("seal: unknown format")
	}
	raw, err := base64.RawStdEncoding.DecodeString(enc)
	if err != nil {
		return "", fmt.Errorf("seal: %w", err)
	}
	n := s.aead.NonceSize()
	if len(raw) < n {
		return "", errors.New("seal: value too short")
	}
	plain, err := s.aead.Open(nil, raw[:n], raw[n:], nil)
	if err != nil {
		return "", errors.New("seal: can't decrypt: wrong ENCRYPTION_KEY or corrupted value")
	}
	return string(plain), nil
}
