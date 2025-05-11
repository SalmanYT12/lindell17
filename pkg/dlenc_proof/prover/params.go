package prover

import (
	"math/big"

	"github.com/primefactor-io/ecc/pkg/weierstrass"
	"github.com/primefactor-io/paillier/pkg/keys"
)

// Params is an instance of parameters for a DLEnc proof prover.
type Params struct {
	curve weierstrass.Curve
	sk    *keys.PrivateKey
	x1    *big.Int
}

// NewParams creates a new instance of parameters for a DLEnc proof prover.
func NewParams(curve weierstrass.Curve, sk *keys.PrivateKey, x1 *big.Int) *Params {
	return &Params{
		curve: curve,
		sk:    sk,
		x1:    x1,
	}
}
