package verifier

import "github.com/primefactor-io/lindell17/pkg/lindell17"

// Result is the result the verifier computed.
type Result struct {
	// Sid is the session id.
	Sid string
	// IsValid indicates if the proof is valid.
	IsValid bool
}

// NewResult creates a new instance of a result the verifier computed.
func NewResult(sid string, isValid bool) *Result {
	return &Result{
		Sid:     sid,
		IsValid: isValid,
	}
}

func (v *Result) From() lindell17.Entity {
	return lindell17.Verifier
}

func (v *Result) Protocol() lindell17.Protocol {
	return lindell17.DLEncProof
}

func (v *Result) SessionId() string {
	return v.Sid
}
