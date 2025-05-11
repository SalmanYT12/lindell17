package messages

import (
	"github.com/primefactor-io/lindell17/pkg/dlenc_proof/messages"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Message5 is the protocol's fifth message that is sent from party 1 to party 2.
// It's a wrapper around the second message the DLEnc proof prover sends to the
// verifier.
type Message5 struct {
	messages.Message2
	// Sid is the session id.
	Sid string
}

// NewMessage5 creates a new instance of the protocol's fifth message.
func NewMessage5(sid string, msg *messages.Message2) *Message5 {
	return &Message5{
		Sid:      sid,
		Message2: *msg,
	}
}

func (m *Message5) To() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message5) From() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message5) Protocol() lindell17.Protocol {
	return lindell17.Keygen
}

func (m *Message5) MessageId() int {
	return 5
}

func (m *Message5) SessionId() string {
	return m.Sid
}

func (m *Message5) IsValid() bool {
	return m.Sid != "" &&
		m.Message2.IsValid()
}
