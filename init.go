package aes256

import (
	"math/big"
)

// modIV is one greater than the maximum IV value
var modIV *big.Int

// modIV is one greater than the maximum nonce value
var modNonce *big.Int

func init() {
	one := big.NewInt(1)
	a := [IVSize]byte{}
	for i := 0; i < len(a); i++ {
		a[i] = 0xff
	}
	modIV = new(big.Int)
	modIV.SetBytes(a[:])
	modIV.Add(modIV, one)

	b := [NonceSize]byte{}
	for i := 0; i < len(a); i++ {
		a[i] = 0xff
	}
	modNonce = new(big.Int)
	modNonce.SetBytes(b[:])
	modNonce.Add(modNonce, one)
}
