package party1

import (
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/ecc/pkg/weierstrass"
	"github.com/primefactor-io/paillier/pkg/keys"
)

// Params is an instance of parameters party 1 uses.
type Params struct {
	curve   weierstrass.Curve
	sk      *keys.PrivateKey
	qShared *elliptic.Point
}

// NewParams creates a new instance of parameters party 1 uses.
func NewParams(curve weierstrass.Curve, sk *keys.PrivateKey, qShared *elliptic.Point) *Params {
	return &Params{
		curve:   curve,
		sk:      sk,
		qShared: qShared,
	}
}
