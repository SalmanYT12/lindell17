package party1

import (
	"github.com/primefactor-io/ecc/pkg/ecdsa"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Result is the result that party 1 computed.
type Result struct {
	// Sid is the session id.
	Sid string
	// PreSignature is the final ECDSA pre-signature that was generated after
	// running the protocol.
	PreSignature *ecdsa.PreSignature
}

// NewResult creates a new instance of a result that party 1 computed.
func NewResult(sid string, preSignature *ecdsa.PreSignature) *Result {
	return &Result{
		Sid:          sid,
		PreSignature: preSignature,
	}
}

func (r *Result) From() lindell17.Entity {
	return lindell17.Party1
}

func (r *Result) Protocol() lindell17.Protocol {
	return lindell17.Adaptor
}

func (r *Result) SessionId() string {
	return r.Sid
}
