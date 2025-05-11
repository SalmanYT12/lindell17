package party1

import (
	"github.com/primefactor-io/ecc/pkg/ecdsa"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// Result is the result that party 1 computed.
type Result struct {
	// Sid is the session id.
	Sid string
	// Signature is the full ECDSA signature that was generated after running the
	// protocol.
	Signature *ecdsa.Signature
}

// NewResult creates a new instance of a result that party 1 computed.
func NewResult(sid string, signature *ecdsa.Signature) *Result {
	return &Result{
		Sid:       sid,
		Signature: signature,
	}
}

func (r *Result) From() lindell17.Entity {
	return lindell17.Party1
}

func (r *Result) Protocol() lindell17.Protocol {
	return lindell17.Sign
}

func (r *Result) SessionId() string {
	return r.Sid
}
