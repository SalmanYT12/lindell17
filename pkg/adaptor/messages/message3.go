package messages

import (
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/ecc/pkg/proofs"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/paillier/pkg/cipher"
)

// Message3 is the protocol's third message that is sent from party 2 to party 1.
type Message3 struct {
	// Sid is the session id.
	Sid string
	// R2 is the value R2.
	R2 *elliptic.Point
	// PR2 is the discrete logarithm knowledge proof for R2.
	PR2 *proofs.DLKProof
	// R2Prime is the value R2'.
	R2Prime *elliptic.Point
	// PK2DLEq is the discrete logarithm equality proof for k2.
	PK2DLEq *proofs.DLEqProof
	// Ciphertext is the encryption of k2^-1 * (z + (r * x1 * x2)) + (p * q).
	Ciphertext cipher.Ciphertext
}

// NewMessage3 creates a new instance of the protocol's third message.
func NewMessage3(sid string, r2 *elliptic.Point, pR2 *proofs.DLKProof, r2Prime *elliptic.Point, pK2DLEq *proofs.DLEqProof, ciphertext cipher.Ciphertext) *Message3 {
	return &Message3{
		Sid:        sid,
		R2:         r2,
		PR2:        pR2,
		R2Prime:    r2Prime,
		PK2DLEq:    pK2DLEq,
		Ciphertext: ciphertext,
	}
}

func (m *Message3) To() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message3) From() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message3) Protocol() lindell17.Protocol {
	return lindell17.Adaptor
}

func (m *Message3) MessageId() int {
	return 3
}

func (m *Message3) SessionId() string {
	return m.Sid
}

func (m *Message3) IsValid() bool {
	return m.Sid != "" &&
		m.R2 != nil &&
		m.PR2 != nil &&
		m.R2Prime != nil &&
		m.PK2DLEq != nil &&
		m.Ciphertext != nil
}
