package aes256

import (
	"crypto/rand"
	"math/big"
	"os"
	"strconv"

	"github.com/etclab/mu"
)

// IVSize is the AES-256 IV size in bytes.
const IVSize = 16

// IVSizeError indicates an invalid IV size.  The integer value of the
// error is the size in bytes of the invalid IV.
type IVSizeError int

func (i IVSizeError) Error() string {
	return "aes256: invalid IV size " + strconv.Itoa(int(i))
}

// ReadIVFile reads an AES-256 IV from a file.  The file should contain
// exactly [IVSize] bytes.  If the file contains a different number of bytes,
// this functions returns an [IVSizeError].
func ReadIVFile(path string) ([]byte, error) {
	iv, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	ivlen := len(iv)
	if ivlen != IVSize {
		return nil, IVSizeError(ivlen)
	}

	return iv, nil
}

// NewRandomIV generates a random AES-256 IV.
func NewRandomIV() []byte {
	iv := make([]byte, IVSize)
	_, err := rand.Read(iv)
	if err != nil {
		mu.Panicf("aes256.GenerateRandomIV: rand.Read failed: %v", err)
	}
	return iv
}

// NewZeroIV generates a zero IV value.
func NewZeroIV() []byte {
	return make([]byte, IVSize)
}

func AddIV(iv []byte, x int) []byte {
	if len(iv) != IVSize {
		mu.Panicf("aes256.AddIV: %v", IVSizeError(len(iv)))
	}
	z := byteSliceToBigInt(iv)
	y := big.NewInt(int64(x))
	z.Add(z, y)
	z.Mod(z, modIV) // This should always be positive
	z.FillBytes(iv)
	return iv
}

func IncIV(iv []byte) []byte {
	return AddIV(iv, 1)
}

func DecIV(iv []byte) []byte {
	return AddIV(iv, -1)
}

func CopyIV(iv []byte) []byte {
	if len(iv) != IVSize {
		mu.Panicf("aes256.CopyIV: %v", IVSizeError(len(iv)))
	}
	_new := make([]byte, len(iv))
	copy(_new, iv)
	return _new
}

func IVToNonce(iv []byte) []byte {
	if len(iv) != IVSize {
		mu.Panicf("aes256.AddIV: %v", IVSizeError(len(iv)))
	}
	_new := CopyIV(iv)
	return _new[(IVSize - NonceSize):]
}
