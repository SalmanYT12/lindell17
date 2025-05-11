package verifier

import (
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/ecc/pkg/weierstrass"
	"github.com/primefactor-io/paillier/pkg/cipher"
	"github.com/primefactor-io/paillier/pkg/keys"
)

// Params is an instance of parameters for a DLEnc proof verifier.
type Params struct {
	curve weierstrass.Curve
	q1    *elliptic.Point
	pk    *keys.PublicKey
	x1Enc cipher.Ciphertext
}

// NewParams creates a new instance of parameters for a DLEnc proof verifier.
func NewParams(curve weierstrass.Curve, q1 *elliptic.Point, pk *keys.PublicKey, x1Enc cipher.Ciphertext) *Params {
	return &Params{
		curve: curve,
		q1:    q1,
		pk:    pk,
		x1Enc: x1Enc,
	}
}
