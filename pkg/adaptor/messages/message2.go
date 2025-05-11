package messages

import (
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/ecc/pkg/proofs"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Message2 is the protocol's second message that is sent from party 1 to party 2.
type Message2 struct {
	// Sid is the session id.
	Sid string
	// R1 is the value R1.
	R1 *elliptic.Point
	// PR1 is the discrete logarithm knowledge proof for R1.
	PR1 *proofs.DLKProof
	// R1Prime is the value R1'.
	R1Prime *elliptic.Point
	// PK1DLEq is the discrete logarithm equality proof for k1.
	PK1DLEq *proofs.DLEqProof
}

// NewMessage2 creates a new instance of the protocol's second message.
func NewMessage2(sid string, r1 *elliptic.Point, pR1 *proofs.DLKProof, r1Prime *elliptic.Point, pK1DLEq *proofs.DLEqProof) *Message2 {
	return &Message2{
		Sid:     sid,
		R1:      r1,
		PR1:     pR1,
		R1Prime: r1Prime,
		PK1DLEq: pK1DLEq,
	}
}

func (m *Message2) To() lindell17.Entity {
	return lindell17.Party2
}

func (m *Message2) From() lindell17.Entity {
	return lindell17.Party1
}

func (m *Message2) Protocol() lindell17.Protocol {
	return lindell17.Adaptor
}

func (m *Message2) MessageId() int {
	return 2
}

func (m *Message2) SessionId() string {
	return m.Sid
}

func (m *Message2) IsValid() bool {
	return m.Sid != "" &&
		m.R1 != nil &&
		m.PR1 != nil &&
		m.R1Prime != nil &&
		m.PK1DLEq != nil
}
