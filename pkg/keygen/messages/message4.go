package messages

import (
	"github.com/primefactor-io/lindell17/pkg/dlenc_proof/messages"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Message4 is the protocol's fourth message that is sent from party 2 to party 1.
// It's a wrapper around the first message the DLEnc proof verifier sends to the
// prover.
type Message4 struct {
	messages.Message1
	// Sid is the session id,
	Sid string
}

// NewMessage4 creates a new instance of the protocol's fourth message.
func NewMessage4(sid string, msg *messages.Message1) *Message4 {
	return &Message4{
		Sid:      sid,
		Message1: *msg,
	}
}

func (m *Message4) To() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message4) From() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message4) Protocol() lindell17.Protocol {
	return lindell17.Keygen
}

func (m *Message4) MessageId() int {
	return 4
}

func (m *Message4) SessionId() string {
	return m.Sid
}

func (m *Message4) IsValid() bool {
	return m.Sid != "" &&
		m.Message1.IsValid()
}
