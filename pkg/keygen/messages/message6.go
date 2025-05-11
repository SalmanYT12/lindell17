package messages

import (
	"github.com/primefactor-io/lindell17/pkg/dlenc_proof/messages"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Message6 is the protocol's sixth message that is sent from party 2 to party 1.
// It's a wrapper around the third message the DLEnc proof verifier sends to the
// prover.
type Message6 struct {
	messages.Message3
	// Sid is the session id.
	Sid string
}

// NewMessage6 creates a new instance of the protocol's sixth message.
func NewMessage6(sid string, msg *messages.Message3) *Message6 {
	return &Message6{
		Sid:      sid,
		Message3: *msg,
	}
}

func (m *Message6) To() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message6) From() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message6) Protocol() lindell17.Protocol {
	return lindell17.Keygen
}

func (m *Message6) MessageId() int {
	return 6
}

func (m *Message6) SessionId() string {
	return m.Sid
}

func (m *Message6) IsValid() bool {
	return m.Sid != "" &&
		m.Message3.IsValid()
}
