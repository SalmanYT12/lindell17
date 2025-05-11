package messages

import (
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Message4 is the protocol's fourth message that is sent from the prover to the
// verifier.
type Message4 struct {
	// Sid is the session id.
	Sid string
	// QHat is the value Q^.
	QHat *elliptic.Point
}

// NewMessage4 creates a new instance of the protocol's fourth message.
func NewMessage4(sid string, qHat *elliptic.Point) *Message4 {
	return &Message4{
		Sid:  sid,
		QHat: qHat,
	}
}

func (m *Message4) To() lindell17.Entity {
	return lindell17.Verifier
}

func (m *Message4) From() lindell17.Entity {
	return lindell17.Prover
}

func (m *Message4) Protocol() lindell17.Protocol {
	return lindell17.DLEncProof
}

func (m *Message4) MessageId() int {
	return 4
}

func (m *Message4) SessionId() string {
	return m.Sid
}

func (m *Message4) IsValid() bool {
	return m.Sid != "" &&
		m.QHat != nil
}
