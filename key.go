package aes256

import (
	"crypto/aes"
	"crypto/rand"
	"os"

	"github.com/etclab/mu"
)

// KeySize is the AES-256 key size in bytes.
const KeySize = 32

// ReadKeyFile reads an AES-256 key from a file.  The file should contain
// exactly [KeySize] bytes.  If the file contains a different number of bytes,
// this functions returns an [aes.KeySizeError].
func ReadKeyFile(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	klen := len(key)
	if klen != KeySize {
		return nil, aes.KeySizeError(klen)
	}

	return key, nil
}

// NewRandomKey generates a random AES-256 key.
func NewRandomKey() []byte {
	key := make([]byte, KeySize)
	_, err := rand.Read(key)
	if err != nil {
		mu.Panicf("aes256.GenerateRandomKey: rand.Read failed: %v", err)
	}
	return key
}
