package party2

import "github.com/primefactor-io/ecc/pkg/weierstrass"

// Params is an instance of parameters party 2 uses.
type Params struct {
	curve            weierstrass.Curve
	rangeProofBits   int
	nthRootProofBits int
}

// NewParams creates a new instance of parameters party 2 uses.
func NewParams(curve weierstrass.Curve, rangeProofBits, nthRootProofBits int) *Params {
	return &Params{
		curve:            curve,
		rangeProofBits:   rangeProofBits,
		nthRootProofBits: nthRootProofBits,
	}
}
