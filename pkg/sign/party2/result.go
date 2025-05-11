package party2

import (
	"math/big"

	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/paillier/pkg/cipher"
)

// Result is the result that party 2 computed.
type Result struct {
	// Sid is the session id.
	Sid string
	// R is the signature's r value.
	R *big.Int
	// Ciphertext is the encryption of k2^-1 * (z + (r * x1 * x2)) + (p * q).
	Ciphertext cipher.Ciphertext
}

// NewResult creates a new instance of a result that party 2 computed.
func NewResult(sid string, r *big.Int, ciphertext cipher.Ciphertext) *Result {
	return &Result{
		Sid:        sid,
		R:          r,
		Ciphertext: ciphertext,
	}
}

func (r *Result) From() lindell17.Entity {
	return lindell17.Party2
}

func (r *Result) Protocol() lindell17.Protocol {
	return lindell17.Sign
}

func (r *Result) SessionId() string {
	return r.Sid
}
