package messages

import (
	"math/big"

	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Message3 is the protocol's third message that is sent from the verifier to
// the prover.
type Message3 struct {
	// Sid is the session id.
	Sid string
	// A is the first randomly sampled value.
	A *big.Int
	// B is the second randomly sampled value.
	B *big.Int
}

// NewMessage3 creates a new instance of the protocol's third message.
func NewMessage3(sid string, a, b *big.Int) *Message3 {
	return &Message3{
		Sid: sid,
		A:   a,
		B:   b,
	}
}

func (m *Message3) To() lindell17.Entity {
	return lindell17.Prover
}

func (m *Message3) From() lindell17.Entity {
	return lindell17.Verifier
}

func (m *Message3) Protocol() lindell17.Protocol {
	return lindell17.DLEncProof
}

func (m *Message3) MessageId() int {
	return 3
}

func (m *Message3) SessionId() string {
	return m.Sid
}

func (m *Message3) IsValid() bool {
	return m.Sid != "" &&
		m.A != nil &&
		m.B != nil
}
