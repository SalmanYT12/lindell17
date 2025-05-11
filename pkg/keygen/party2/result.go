package party2

import (
	"math/big"

	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/paillier/pkg/cipher"
	"github.com/primefactor-io/paillier/pkg/keys"
)

// Result is the result that party 2 computed.
type Result struct {
	// Sid is the session id.
	Sid string
	// KeyMaterial is the key material that was derived after running the protocol.
	KeyMaterial *KeyMaterial
}

// NewResult creates a new instance of a result that party 2 computed.
func NewResult(sid string, keyMaterial *KeyMaterial) *Result {
	return &Result{
		Sid:         sid,
		KeyMaterial: keyMaterial,
	}
}

func (r *Result) From() lindell17.Entity {
	return lindell17.Party2
}

func (r *Result) Protocol() lindell17.Protocol {
	return lindell17.Keygen
}

func (r *Result) SessionId() string {
	return r.Sid
}

// KeyMaterial is an instance of party 2's key material which is the result of
// running the key generation protocol.
type KeyMaterial struct {
	// X1Enc is the encrypted private key share of party 1.
	X1Enc cipher.Ciphertext
	// X2 is party 2's private key share.
	X2 *big.Int
	// Pk is party 1's Paillier public key.
	Pk *keys.PublicKey
	// Q is the shared secret.
	Q *elliptic.Point
}

// NewKeyMaterial creates a new instance of party 2's key material which is the
// result of running the key generation protocol.
func NewKeyMaterial(x1Enc cipher.Ciphertext, x2 *big.Int, pk *keys.PublicKey, q *elliptic.Point) *KeyMaterial {
	return &KeyMaterial{
		X1Enc: x1Enc,
		X2:    x2,
		Pk:    pk,
		Q:     q,
	}
}
