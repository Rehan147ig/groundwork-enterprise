// Connector credential metadata encryption (Milestone 3).
//
// Installations must never store client secrets in plaintext. This file
// provides AES-256-GCM envelope encryption: the key material comes from
// the keyring's connector purpose (keyring.PurposeConnector), and every
// ciphertext is bound to a per-field AAD context so ciphertexts cannot
// be replayed across tenants or fields.
package keyring

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

var (
	// ErrCiphertextTooShort marks a truncated/foreign ciphertext.
	ErrCiphertextTooShort = errors.New("keyring: ciphertext too short")
	// ErrCiphertextTampered marks a failed AEAD authentication (wrong key,
	// corrupted blob, or AAD mismatch).
	ErrCiphertextTampered = errors.New("keyring: ciphertext authentication failed")
)

// EncryptConnectorMetadata seals plaintext with AES-256-GCM using the
// connector purpose key. aad binds the ciphertext to its logical
// location (e.g. "tenant_id=<id>:provider=msgraph:field=credential");
// callers MUST pass the same aad to Decrypt. The 16-byte nonce is
// prepended to the ciphertext.
func EncryptConnectorMetadata(ctx context.Context, k *Keyring, aad string, plaintext []byte) ([]byte, error) {
	key, err := k.Get(ctx, PurposeConnector)
	if err != nil {
		return nil, err
	}
	return encryptWithKey(key.Secret, aad, plaintext)
}

// DecryptConnectorMetadata is the inverse of EncryptConnectorMetadata.
// Any failure (missing key, tamper, wrong aad) returns an error — never
// partially decrypted data.
func DecryptConnectorMetadata(ctx context.Context, k *Keyring, aad string, ciphertext []byte) ([]byte, error) {
	key, err := k.Get(ctx, PurposeConnector)
	if err != nil {
		return nil, err
	}
	return decryptWithKey(key.Secret, aad, ciphertext)
}

// encryptWithKey derives a fixed 32-byte AES key from the purpose key
// material (SHA-256 of the raw secret; the secret may be a long
// passphrase) and seals plaintext with AES-256-GCM.
func encryptWithKey(material []byte, aad string, plaintext []byte) ([]byte, error) {
	if len(material) == 0 {
		return nil, fmt.Errorf("%w: connector", ErrKeyMissing)
	}
	sum := sha256.Sum256(material)
	block, err := aes.NewCipher(sum[:])
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
	return gcm.Seal(nonce, nonce, plaintext, []byte(aad)), nil
}

func decryptWithKey(material []byte, aad string, ciphertext []byte) ([]byte, error) {
	if len(material) == 0 {
		return nil, fmt.Errorf("%w: connector", ErrKeyMissing)
	}
	sum := sha256.Sum256(material)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, ErrCiphertextTooShort
	}
	nonce, sealed := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, sealed, []byte(aad))
	if err != nil {
		return nil, ErrCiphertextTampered
	}
	return plain, nil
}
