package messages

import (
	"github.com/primefactor-io/ecc/pkg/ecdsa"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Message4 is the protocol's fourth message that is sent from party 1 to party 2.
type Message4 struct {
	// Sid is the session id.
	Sid string
	// PreSig is the final ECDSA pre-signature.
	PreSig *ecdsa.PreSignature
}

// NewMessage4 creates a new instance of the protocol's fourth message.
func NewMessage4(sid string, preSig *ecdsa.PreSignature) *Message4 {
	return &Message4{
		Sid:    sid,
		PreSig: preSig,
	}
}

func (m *Message4) To() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message4) From() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message4) Protocol() lindell17.Protocol {
	return lindell17.Adaptor
}

func (m *Message4) MessageId() int {
	return 4
}

func (m *Message4) SessionId() string {
	return m.Sid
}

func (m *Message4) IsValid() bool {
	return m.Sid != "" &&
		m.PreSig != nil

}
