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
	// R2 is the value R2.
	R2 *elliptic.Point
	// PR2 is the discrete logarithm knowledge proof for R2.
	PR2 *proofs.DLKProof
}

// NewMessage2 creates a new instance of the protocol's second message.
func NewMessage2(sid string, r2 *elliptic.Point, pR2 *proofs.DLKProof) *Message2 {
	return &Message2{
		Sid: sid,
		R2:  r2,
		PR2: pR2,
	}
}

func (m *Message2) To() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message2) From() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message2) Protocol() lindell17.Protocol {
	return lindell17.Sign
}

func (m *Message2) MessageId() int {
	return 2
}

func (m *Message2) SessionId() string {
	return m.Sid
}

func (m *Message2) IsValid() bool {
	return m.Sid != "" &&
		m.R2 != nil &&
		m.PR2 != nil
}
