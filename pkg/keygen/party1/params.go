package party1

import "github.com/primefactor-io/ecc/pkg/weierstrass"

// Params is an instance of parameters party 1 uses.
type Params struct {
	curve            weierstrass.Curve
	rangeProofBits   int
	nthRootProofBits int
	paillierBits     int
}

// NewParams creates a new instance of parameters party 1 uses.
func NewParams(curve weierstrass.Curve, rangeProofBits, nthRootProofBits, paillierBits int) *Params {
	return &Params{
		curve:            curve,
		rangeProofBits:   rangeProofBits,
		nthRootProofBits: nthRootProofBits,
		paillierBits:     paillierBits,
	}
}
