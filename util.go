package aes256

import (
	"math/big"
)

func byteSliceToBigInt(b []byte) *big.Int {
	z := new(big.Int)
	z.SetBytes(b)
	return z
}
