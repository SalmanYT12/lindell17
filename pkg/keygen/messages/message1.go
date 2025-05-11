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
	// CQ1 is the commitment to Q1.
	CQ1 *hash.Commitment
	// PQ1 is the discrete logarithm knowledge proof for Q1.
	PQ1 *proofs.DLKProof
}

// NewMessage1 creates a new instance of the protocol's first message.
func NewMessage1(sid string, cQ1 *hash.Commitment, pQ1 *proofs.DLKProof) *Message1 {
	return &Message1{
		Sid: sid,
		CQ1: cQ1,
		PQ1: pQ1,
	}
}

func (m *Message1) To() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message1) From() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message1) Protocol() lindell17.Protocol {
	return lindell17.Keygen
}

func (m *Message1) MessageId() int {
	return 1
}

func (m *Message1) SessionId() string {
	return m.Sid
}

func (m *Message1) IsValid() bool {
	return m.Sid != "" &&
		m.CQ1 != nil &&
		m.PQ1 != nil
}
