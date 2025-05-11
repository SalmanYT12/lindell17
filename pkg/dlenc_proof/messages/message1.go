package messages

import (
	"github.com/primefactor-io/commitment/pkg/hash"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/paillier/pkg/cipher"
)

// Message1 is the protocol's first message that is sent from the verifier to
// the prover.
type Message1 struct {
	// Sid is the session id.
	Sid string
	// CRandVals is the commitment to the randomly sampled values a and b.
	CRandVals *hash.Commitment
	// Ciphertext is the encryption of (x1 * a) + b.
	Ciphertext cipher.Ciphertext
}

// NewMessage1 creates a new instance of the protocol's first message.
func NewMessage1(sid string, cRandVals *hash.Commitment, ciphertext cipher.Ciphertext) *Message1 {
	return &Message1{
		Sid:        sid,
		CRandVals:  cRandVals,
		Ciphertext: ciphertext,
	}
}

func (m *Message1) To() lindell17.Entity {
	return lindell17.Prover
}

func (m *Message1) From() lindell17.Entity {
	return lindell17.Verifier
}

func (m *Message1) Protocol() lindell17.Protocol {
	return lindell17.DLEncProof
}

func (m *Message1) MessageId() int {
	return 1
}

func (m *Message1) SessionId() string {
	return m.Sid
}

func (m *Message1) IsValid() bool {
	return m.Sid != "" &&
		m.CRandVals != nil &&
		m.Ciphertext != nil
}
