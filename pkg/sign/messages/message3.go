package messages

import (
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Message3 is the protocol's third message that is sent from party 1 to party 2.
type Message3 struct {
	// Sid is the session id.
	Sid string
	// R1 is the value R1.
	R1 *elliptic.Point
}

// NewMessage3 creates a new instance of the protocol's third message.
func NewMessage3(sid string, r1 *elliptic.Point) *Message3 {
	return &Message3{
		Sid: sid,
		R1:  r1,
	}
}

func (m *Message3) To() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message3) From() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message3) Protocol() lindell17.Protocol {
	return lindell17.Sign
}

func (m *Message3) MessageId() int {
	return 3
}

func (m *Message3) SessionId() string {
	return m.Sid
}

func (m *Message3) IsValid() bool {
	return m.Sid != "" &&
		m.R1 != nil
}
