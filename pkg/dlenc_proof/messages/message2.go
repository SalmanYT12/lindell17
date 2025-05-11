package messages

import (
	"github.com/primefactor-io/commitment/pkg/hash"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Message2 is the protocol's second message that is sent from the prover to the
// verifier.
type Message2 struct {
	// Sid is the session id.
	Sid string
	// CQHat is the commitment to Q^.
	CQHat *hash.Commitment
}

// NewMessage2 creates a new instance of the protocol's second message.
func NewMessage2(sid string, cQHat *hash.Commitment) *Message2 {
	return &Message2{
		Sid:   sid,
		CQHat: cQHat,
	}
}

func (m *Message2) To() lindell17.Entity {
	return lindell17.Verifier
}

func (m *Message2) From() lindell17.Entity {
	return lindell17.Prover
}

func (m *Message2) Protocol() lindell17.Protocol {
	return lindell17.DLEncProof
}

func (m *Message2) MessageId() int {
	return 2
}

func (m *Message2) SessionId() string {
	return m.Sid
}

func (m *Message2) IsValid() bool {
	return m.Sid != "" &&
		m.CQHat != nil
}
