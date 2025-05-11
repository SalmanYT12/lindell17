package lindell17

// Message is an interface that all protocol messages need to implement.
type Message interface {
	// To returns the entity the message should be sent to.
	To() Entity
	// From returns the entity the message originated from.
	From() Entity
	// Protocol returns the protocol the message belongs to.
	Protocol() Protocol
	// MessageId returns the protocol's message id.
	MessageId() int
	// SessionId returns the protocol run's session id.
	SessionId() string
	// IsValid checks if the message and its content are valid.
	IsValid() bool
}

// Result is an interface that all protocol results need to implement.
type Result interface {
	// From returns the entity that produces the result.
	From() Entity
	// Protocol returns the protocol the result belongs to.
	Protocol() Protocol
	// SessionId returns the protocol run's session id.
	SessionId() string
}

// Protocol indicates the protocol that's used.
type Protocol int

const (
	// DLEncProof is the protocol for the interactive discrete log encryption proof.
	DLEncProof = iota
	// KeyGen is the protocol to generate keys.
	Keygen
	// Sign is the protocol to generate signatures.
	Sign
	// Adaptor is the protocol to generate adaptor signatures.
	Adaptor
)

// Entity is used to indicate a protocol's entity.
type Entity int

const (
	// Party1 is the entity for party 1.
	Party1 = iota
	// Party2 is the entity for party 2.
	Party2
	// Prover is the entity for a prover.
	Prover
	// Verifier is the entity for a verifier.
	Verifier
)

// State is used to indicate an internal state.
type State int

const (
	// Start is the initial state.
	Start State = iota
	// Step1 is the first state.
	Step1
	// Step2 is the second state.
	Step2
	// Step3 is the third state.
	Step3
	// Step4 is the fourth state.
	Step4
)
