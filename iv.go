package aes256

import (
	"crypto/rand"
	"math/big"
	"os"
	"strconv"

	"github.com/etclab/mu"
)

// IVSize is the AES IV size in bytes.
const IVSize = 16

// IVSizeError indicates an invalid IV size.  The integer value of the
// error is the size in bytes of the invalid IV.
type IVSizeError int

func (i IVSizeError) Error() string {
	return "aes256: invalid IV size " + strconv.Itoa(int(i))
}

// ReadIVFile reads an AES IV from a file.  The file should contain
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

// NewRandomIV generates a random AES IV.
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

// AddIV adds x to the iv value, handling wrap-around when the iv
// would exceed [IVSize] bytes.  iv is an in-out parameter, as well
// as the return value.
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

// IncIV increments the iv value by one, handling wrap-around when the iv
// would exceed [IVSize] bytes.  iv is an in-out parameter, as well
// as the return value.
func IncIV(iv []byte) []byte {
	return AddIV(iv, 1)
}

// DecIV decrements the iv value by one, handling wrap-around when the iv would
// become negative.  iv is an in-out parameter, as well as the return value.
func DecIV(iv []byte) []byte {
	return AddIV(iv, -1)
}

// CopyIV makes a deep copy of the iv and returns the copy.
func CopyIV(iv []byte) []byte {
	if len(iv) != IVSize {
		mu.Panicf("aes256.CopyIV: %v", IVSizeError(len(iv)))
	}
	_new := make([]byte, len(iv))
	copy(_new, iv)
	return _new
}

// IVToNonce makes a copy of iv, truncated to [NonceSize].
func IVToNonce(iv []byte) []byte {
	if len(iv) != IVSize {
		mu.Panicf("aes256.AddIV: %v", IVSizeError(len(iv)))
	}
	_new := CopyIV(iv)
	return _new[(IVSize - NonceSize):]
}
