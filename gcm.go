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
// the plaintext.  Note that this function overwrites the data slice to hold
// the ciphertext and tag.  Since the addition of the tag may cause a new
// allocation, the caller should use the return slice as the output value,
// rather than treat data as an in-out parameter.
func EncryptGCM(key, nonce, data, additionalData []byte) []byte {
	aead := NewGCM(key)
	return aead.Seal(data[:0], nonce, data, additionalData)
}

// SplitCiphertextTag takes as input an AES-256 GCM encrypted ciphertext
// and returns the two components of the ciphertext: the ciphertext proper, and
// the authentication tag (which is conventionally appended to the ciphertext).
func SplitCiphertextTag(ciphertext []byte) ([]byte, []byte, error) {
	if len(ciphertext) < TagSize {
		return nil, nil, fmt.Errorf("ciphertext (%d bytes) < AES GCM tag size (%d)", len(ciphertext), TagSize)
	}

	tag := ciphertext[len(ciphertext)-TagSize:]
	ciphertext = ciphertext[:len(ciphertext)-TagSize]
	return ciphertext, tag, nil
}

// DecryptGCM performs a one-shot AES-256 GCM decryption and authentication of
// the ciphertext data and additionalData.   Note that this function overwrites
// the data slice to hold the plaintext.  On success, the function returns the
// plaintext.  Callers should generally use the return value, rather than
// treat data as an in-put parameter.
func DecryptGCM(key, nonce, data, additionalData []byte) ([]byte, error) {
	aead := NewGCM(key)
	return aead.Open(data[:0], nonce, data, additionalData)
}
