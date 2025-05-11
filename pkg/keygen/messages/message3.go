package messages

import (
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/paillier/pkg/cipher"
	"github.com/primefactor-io/paillier/pkg/keys"
	"github.com/primefactor-io/paillier/pkg/proofs"
)

// Message3 is the protocol's third message that is sent from party 1 to party 2.
type Message3 struct {
	// Sid is the session id.
	Sid string
	// Q1 is the value Q1.
	Q1 *elliptic.Point
	// Pk is the Paillier public key.
	Pk *keys.PublicKey
	// PNthRoot is the proof of knowledge of an Nth Root.
	PNthRoot *proofs.NthRootProof
	// X1Enc is the Paillier encryption of x1.
	X1Enc cipher.Ciphertext
	// PRange is the range proof.
	PRange *proofs.RangeProof
}

// NewMessage3 creates a new instance of the protocol's third message.
func NewMessage3(sid string, q1 *elliptic.Point, pk *keys.PublicKey, pNthRoot *proofs.NthRootProof, x1Enc cipher.Ciphertext, pRange *proofs.RangeProof) *Message3 {
	return &Message3{
		Sid:      sid,
		Q1:       q1,
		Pk:       pk,
		PNthRoot: pNthRoot,
		X1Enc:    x1Enc,
		PRange:   pRange,
	}
}

func (m *Message3) To() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message3) From() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message3) Protocol() lindell17.Protocol {
	return lindell17.Keygen
}

func (m *Message3) MessageId() int {
	return 3
}

func (m *Message3) SessionId() string {
	return m.Sid
}

func (m *Message3) IsValid() bool {
	return m.Sid != "" &&
		m.Q1 != nil &&
		m.Pk != nil &&
		m.PNthRoot != nil &&
		m.X1Enc != nil &&
		m.PRange != nil
}
