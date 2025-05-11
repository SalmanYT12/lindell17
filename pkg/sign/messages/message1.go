package messages

import (
	"github.com/primefactor-io/commitment/pkg/hash"
	"github.com/primefactor-io/ecc/pkg/proofs"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Message1 is the protocol's first message that is sent from party 1 to party 2.
type Message1 struct {
	// Sid is the session id.
	Sid string
	// CR1 is the commitment to R1.
	CR1 *hash.Commitment
	// PR1 is the discrete logarithm knowledge proof for R1.
	PR1 *proofs.DLKProof
}

// NewMessage1 creates a new instance of the protocol's first message.
func NewMessage1(sid string, cR1 *hash.Commitment, pR1 *proofs.DLKProof) *Message1 {
	return &Message1{
		Sid: sid,
		CR1: cR1,
		PR1: pR1,
	}
}

func (m *Message1) To() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message1) From() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message1) Protocol() lindell17.Protocol {
	return lindell17.Sign
}

func (m *Message1) MessageId() int {
	return 1
}

func (m *Message1) SessionId() string {
	return m.Sid
}

func (m *Message1) IsValid() bool {
	return m.Sid != "" &&
		m.CR1 != nil &&
		m.PR1 != nil
}
