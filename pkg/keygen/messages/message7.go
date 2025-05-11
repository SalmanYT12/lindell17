package messages

import (
	"github.com/primefactor-io/lindell17/pkg/dlenc_proof/messages"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Message7 is the protocol's seventh message that is sent from party 1 to
// party 2.
// It's a wrapper around the fourth message the DLEnc proof prover sends to the
// verifier.
type Message7 struct {
	messages.Message4
	// Sid is the session id.
	Sid string
}

// NewMessage7 creates a new instance of the protocol's seventh message.
func NewMessage7(sid string, msg *messages.Message4) *Message7 {
	return &Message7{
		Sid:      sid,
		Message4: *msg,
	}
}

func (m *Message7) To() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message7) From() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message7) Protocol() lindell17.Protocol {
	return lindell17.Keygen
}

func (m *Message7) MessageId() int {
	return 7
}

func (m *Message7) SessionId() string {
	return m.Sid
}

func (m *Message7) IsValid() bool {
	return m.Sid != "" &&
		m.Message4.IsValid()
}
