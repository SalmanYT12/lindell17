package party2

import (
	"math/big"

	"github.com/primefactor-io/ecc/pkg/weierstrass"
	"github.com/primefactor-io/paillier/pkg/cipher"
	"github.com/primefactor-io/paillier/pkg/keys"
)

// Params is an instance of parameters party 2 uses.
type Params struct {
	curve weierstrass.Curve
	pk    *keys.PublicKey
	x1Enc cipher.Ciphertext
	x2    *big.Int
}

// NewParams creates a new instance of parameters party 2 uses.
func NewParams(curve weierstrass.Curve, pk *keys.PublicKey, x1Enc cipher.Ciphertext, x2 *big.Int) *Params {
	return &Params{
		curve: curve,
		pk:    pk,
		x1Enc: x1Enc,
		x2:    x2,
	}
}
