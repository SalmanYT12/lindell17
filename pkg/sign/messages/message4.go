package messages

import (
	"math/big"

	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/paillier/pkg/cipher"
)

// Message4 is the protocol's fourth message that is sent from part 2 to party 1.
type Message4 struct {
	// Sid is the session id.
	Sid string
	// R is the signature's r value.
	R *big.Int
	// Ciphertext is the encryption of k2^-1 * (z + (r * x1 * x2)) + (p * q).
	Ciphertext cipher.Ciphertext
}

// NewMessage4 creates a new instance of the protocol's fourth message.
func NewMessage4(sid string, r *big.Int, ciphertext cipher.Ciphertext) *Message4 {
	return &Message4{
		Sid:        sid,
		R:          r,
		Ciphertext: ciphertext,
	}
}

func (m *Message4) To() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message4) From() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message4) Protocol() lindell17.Protocol {
	return lindell17.Sign
}

func (m *Message4) MessageId() int {
	return 4
}

func (m *Message4) SessionId() string {
	return m.Sid
}

func (m *Message4) IsValid() bool {
	return m.Sid != "" &&
		m.R != nil &&
		m.Ciphertext != nil
}
