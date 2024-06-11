package aes256

import (
	"crypto/rand"
	"math/big"
	"os"
	"strconv"

	"github.com/etclab/mu"
)

// NonceSize is the AES-256 GCM nonce size in bytes.
const NonceSize = 12

// NonceSizeError indicates an invalid nonce size.  The integer value of the
// error is the size in bytes of the invalid nonce.
type NonceSizeError int

func (n NonceSizeError) Error() string {
	return "aes256: invalid nonce size " + strconv.Itoa(int(n))
}

// ReadNonceFile reads an AES-256 GCM nonc from a file.  The file should contain
// exactly [NonceSize] bytes.  If the file contains a different number of bytes,
// this functions returns an [NonceSizeError].
func ReadNonceFile(path string) ([]byte, error) {
	nonce, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	noncelen := len(nonce)
	if noncelen != NonceSize {
		return nil, NonceSizeError(noncelen)
	}

	return nonce, nil
}

// NewRandomNonce generates a random nonce for AES-256 GCM mode.
func NewRandomNonce() []byte {
	nonce := make([]byte, NonceSize)
	_, err := rand.Read(nonce)
	if err != nil {
		mu.Panicf("aes256.GenerateRandomNonce: rand.Read failed: %v", err)
	}
	return nonce
}

// NewZeroNonce generates a zero nonce value for AES-256 GCM mode.
func NewZeroNonce() []byte {
	return make([]byte, NonceSize)
}

func AddNonce(nonce []byte, x int) []byte {
	if len(nonce) != NonceSize {
		mu.Panicf("aes256.AddNonce: %v", NonceSizeError(len(nonce)))
	}
	z := byteSliceToBigInt(nonce)
	y := big.NewInt(int64(x))
	z.Add(z, y)
	z.Mod(z, modNonce) // This should always be positive
	z.FillBytes(nonce)
	return nonce
}

func IncNonce(nonce []byte) []byte {
	return AddNonce(nonce, 1)
}

func DecNonce(nonce []byte) []byte {
	return AddNonce(nonce, -1)
}

func CopyNonce(nonce []byte) []byte {
	if len(nonce) != NonceSize {
		mu.Panicf("aes256.CopyNonce: %v", NonceSizeError(len(nonce)))
	}
	_new := make([]byte, len(nonce))
	copy(_new, nonce)
	return _new
}
