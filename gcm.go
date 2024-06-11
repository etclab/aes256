package aes256

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/etclab/mu"
)

// NewGCM creates a [cipher.AEAD] for AES-256 GCM mode.
func NewGCM(key []byte) cipher.AEAD {
	if len(key) != KeySize {
		mu.Panicf("aes256.NewGCM: bad key size %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		mu.Panicf("aes256.NewGCM: aes.NewCipher: %v", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		mu.Panicf("aes256.NewGCM: cipher.NewGCM: %v", err)
	}

	return aead
}

// EncryptGCM performs a one-shot AES-256 GCM encryption operation and returns
// the plaintext.  Note that this function may reuse the data slice to hold
// the ciphertext and tag.  Thus the caller must not assume that data stil
// holds the plaintext when this function returns.
func EncryptGCM(data, additionalData, key, nonce []byte) []byte {
	aead := NewGCM(key)
	return aead.Seal(data[:0], nonce, data, additionalData)
}

// SplitCiphertextTag takes as input an AES-256 GCM encrypted ciphertext
// and returns the two components of the ciphertext: the ciphertext proper, and
// the authentication tag (which is conventionally appended to the ciphertext).
func SplitCiphertextTag(ciphertext []byte) ([]byte, []byte, error) {
	if len(ciphertext) <= TagSize {
		return nil, nil, fmt.Errorf("ciphertext (%d bytes) <= AES GCM tag size (%d)", len(ciphertext), TagSize)
	}

	tag := ciphertext[len(ciphertext)-TagSize:]
	ciphertext = ciphertext[:len(ciphertext)-TagSize]
	return ciphertext, tag, nil
}

// DecryptGCM performs a one-shot AES-256 GCM decryption and authentication of
// the ciphertext data and additionalData.  Note that this function may reuse
// the data slice to hold the plaintext.  On success, the function returns the
// plaintext.
func DecryptGCM(data, additionalData, key, nonce []byte) ([]byte, error) {
	aead := NewGCM(key)
	return aead.Open(data[:0], nonce, data, additionalData)
}
