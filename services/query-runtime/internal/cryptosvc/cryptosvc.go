// Package cryptosvc implements Phase "Payload Encryption at Rest &
// In-Transit": envelope encryption for sensitive payloads and fields.
//
// An Envelope holds a key-encryption-key (KEK) reference and resolves
// the KEK through a KMS-ready resolver (environment, file, keyring, or
// an AWS/Azure/Vault adapter implementing KEKResolver). Every sealed
// payload gets a fresh data-encryption-key (DEK); the DEK is wrapped by
// the KEK with AES-256-GCM, and only the wrapped key + nonce +
// ciphertext are persisted. Rotating the KEK reference re-encrypts
// nothing at rest: unwrap with the old KEK, re-seal with the new one.
//
// Vector embeddings remain searchable; only the payload fields are
// encrypted. All failures fail closed: an unresolvable KEK, a malformed
// blob, or a tampered ciphertext returns an error and never returns
// plaintext.
package cryptosvc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// ErrKEKUnavailable reports that the configured key-encryption-key
// could not be resolved. Callers must fail closed.
var ErrKEKUnavailable = errors.New("cryptosvc: key encryption key unavailable")

// ErrCiphertextInvalid reports a malformed or tampered ciphertext blob.
// Content is never returned on this error.
var ErrCiphertextInvalid = errors.New("cryptosvc: ciphertext invalid or tampered")

// KEKResolver resolves a key-encryption-key reference to a 32-byte key.
// Implementations exist for environment variables (env://NAME),
// files (file://PATH), and can be adapted to AWS KMS / Azure Key
// Vault / HashiCorp Vault (which generate/return KEKs without
// exposing raw material at rest).
type KEKResolver interface {
	ResolveKEK(ctx context.Context, ref string) ([]byte, error)
}

// blobFormat is the on-disk envelope layout:
//
//	0..6   "GWENC1\0"        magic
//	6..8   uint16 BE         wrapped key length (n)
//	8..8+n wrapped DEK       AES-GCM seal of the 32-byte DEK under the KEK
//	rest   AES-GCM seal of the payload under the DEK (nonce+ciphertext+tag)
const blobFormat = "GWENC1\x00"

// Envelope seals and opens payloads with envelope encryption.
type Envelope struct {
	resolver KEKResolver
	ref      string

	mu  sync.Mutex
	kek []byte
}

// NewEnvelope builds an envelope bound to one KEK reference. The KEK is
// resolved lazily on first use (fail closed if resolution fails).
func NewEnvelope(resolver KEKResolver, ref string) *Envelope {
	return &Envelope{resolver: resolver, ref: ref}
}

// Seal encrypts plaintext with a fresh DEK and returns the envelope
// blob (safe for storage at rest).
func (e *Envelope) Seal(ctx context.Context, plaintext []byte) ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("cryptosvc: generate dek: %w", err)
	}
	kek, err := e.key(ctx)
	if err != nil {
		return nil, err
	}
	wrapped, err := aesGCMSeal(kek, dek, nil)
	if err != nil {
		return nil, err
	}
	sealed, err := aesGCMSeal(dek, plaintext, nil)
	if err != nil {
		return nil, err
	}
	if len(wrapped) > 0xffff {
		return nil, errors.New("cryptosvc: wrapped key too large")
	}
	out := make([]byte, 0, len(blobFormat)+2+len(wrapped)+len(sealed))
	out = append(out, blobFormat...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(wrapped)))
	out = append(out, wrapped...)
	out = append(out, sealed...)
	return out, nil
}

// Open decrypts an envelope blob produced by Seal. It verifies the
// magic, unwraps the DEK with the KEK, and authenticates the payload —
// any tampering fails closed with ErrCiphertextInvalid.
func (e *Envelope) Open(ctx context.Context, blob []byte) ([]byte, error) {
	if len(blob) < len(blobFormat)+2+16+16 || !strings.HasPrefix(string(blob), blobFormat) {
		return nil, ErrCiphertextInvalid
	}
	kek, err := e.key(ctx)
	if err != nil {
		return nil, err
	}
	wrappedLen := int(binary.BigEndian.Uint16(blob[len(blobFormat):]))
	offset := len(blobFormat) + 2
	if offset+wrappedLen > len(blob) {
		return nil, ErrCiphertextInvalid
	}
	wrapped := blob[offset : offset+wrappedLen]
	sealed := blob[offset+wrappedLen:]
	dek, err := aesGCMOpen(kek, wrapped, nil)
	if err != nil {
		return nil, ErrCiphertextInvalid
	}
	plaintext, err := aesGCMOpen(dek, sealed, nil)
	if err != nil {
		return nil, ErrCiphertextInvalid
	}
	return plaintext, nil
}

// EncryptField seals a string field and returns a base64 envelope blob.
func (e *Envelope) EncryptField(ctx context.Context, plaintext string) (string, error) {
	blob, err := e.Seal(ctx, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(blob), nil
}

// DecryptField opens a base64 envelope blob produced by EncryptField.
func (e *Envelope) DecryptField(ctx context.Context, blob string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", ErrCiphertextInvalid
	}
	plaintext, err := e.Open(ctx, raw)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func (e *Envelope) key(ctx context.Context) ([]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.kek) != 0 {
		return e.kek, nil
	}
	if e.resolver == nil {
		return nil, ErrKEKUnavailable
	}
	kek, err := e.resolver.ResolveKEK(ctx, e.ref)
	if err != nil {
		return nil, err
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("%w: resolver returned %d bytes, want 32", ErrKEKUnavailable, len(kek))
	}
	e.kek = append([]byte(nil), kek...)
	return e.kek, nil
}

func aesGCMSeal(key, plaintext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, additionalData), nil
}

func aesGCMOpen(key, blob, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, ErrCiphertextInvalid
	}
	nonce, ciphertext := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, additionalData)
}

// ---- KEK resolvers ----

// EnvKEK resolves env://NAME references to the raw value of environment
// variable NAME. A 32-byte key is required; shorter values are derived
// with SHA-256 so operators can configure a passphrase of any length.
type EnvKEK struct{}

func (EnvKEK) ResolveKEK(_ context.Context, ref string) ([]byte, error) {
	name, ok := strings.CutPrefix(ref, "env://")
	if !ok || name == "" {
		return nil, fmt.Errorf("%w: %q is not an env:// reference", ErrKEKUnavailable, ref)
	}
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return nil, fmt.Errorf("%w: environment variable %s is empty", ErrKEKUnavailable, name)
	}
	if len(value) == 32 {
		return []byte(value), nil
	}
	sum := sha256.Sum256([]byte(value))
	return sum[:], nil
}

// FileKEK resolves file://PATH references by reading the file's bytes
// (32 bytes exactly, or any length hashed with SHA-256).
type FileKEK struct{}

func (FileKEK) ResolveKEK(_ context.Context, ref string) ([]byte, error) {
	path, ok := strings.CutPrefix(ref, "file://")
	if !ok || path == "" {
		return nil, fmt.Errorf("%w: %q is not a file:// reference", ErrKEKUnavailable, ref)
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", ErrKEKUnavailable, path, err)
	}
	if len(value) == 32 {
		return value, nil
	}
	sum := sha256.Sum256(value)
	return sum[:], nil
}

// StaticKEK is a direct in-memory KEK for tests and embedded use.
type StaticKEK struct {
	Key []byte
}

func (s StaticKEK) ResolveKEK(_ context.Context, _ string) ([]byte, error) {
	if len(s.Key) == 32 {
		return s.Key, nil
	}
	return nil, fmt.Errorf("%w: static key must be 32 bytes", ErrKEKUnavailable)
}

// ResolverChain tries each resolver in order, returning the first
// successful key. A resolver that does not own the reference format
// must return an error so the chain moves on.
type ResolverChain []KEKResolver

func (c ResolverChain) ResolveKEK(ctx context.Context, ref string) ([]byte, error) {
	var lastErr error = ErrKEKUnavailable
	for _, resolver := range c {
		key, err := resolver.ResolveKEK(ctx, ref)
		if err == nil {
			return key, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
