package messages

import (
	"github.com/primefactor-io/commitment/pkg/hash"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Message1 is the protocol's first message that is sent from party 2 to party 1.
type Message1 struct {
	// Sid is the session id.
	Sid string
	// CR2 is the commitment to R2.
	CR2 *hash.Commitment
	// CR2Prime is the commitment to R2'.
	CR2Prime *hash.Commitment
}

// NewMessage1 creates a new instance of the protocol's first message.
func NewMessage1(sid string, cR2 *hash.Commitment, cR2Prime *hash.Commitment) *Message1 {
	return &Message1{
		Sid:      sid,
		CR2:      cR2,
		CR2Prime: cR2Prime,
	}
}

func (m *Message1) To() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message1) From() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message1) Protocol() lindell17.Protocol {
	return lindell17.Adaptor
}

func (m *Message1) MessageId() int {
	return 1
}

func (m *Message1) SessionId() string {
	return m.Sid
}

func (m *Message1) IsValid() bool {
	return m.Sid != "" &&
		m.CR2 != nil &&
		m.CR2Prime != nil
}
