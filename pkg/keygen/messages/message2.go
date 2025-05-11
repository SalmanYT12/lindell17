package messages

import (
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/ecc/pkg/proofs"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Message2 is the protocol's second message that is sent form party 2 to party 1.
type Message2 struct {
	// Sid is the session id.
	Sid string
	// Q2 is the value Q2.
	Q2 *elliptic.Point
	// PQ2 is the discrete logarithm knowledge proof for Q2.
	PQ2 *proofs.DLKProof
}

// NewMessage2 creates a new instance of the protocol's second message.
func NewMessage2(sid string, q2 *elliptic.Point, pQ2 *proofs.DLKProof) *Message2 {
	return &Message2{
		Sid: sid,
		Q2:  q2,
		PQ2: pQ2,
	}
}

func (m *Message2) To() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message2) From() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message2) Protocol() lindell17.Protocol {
	return lindell17.Keygen
}

func (m *Message2) MessageId() int {
	return 2
}

func (m *Message2) SessionId() string {
	return m.Sid
}

func (m *Message2) IsValid() bool {
	return m.Sid != "" &&
		m.Q2 != nil &&
		m.PQ2 != nil
}
