package prover

import (
	"math/big"

	"github.com/primefactor-io/commitment/pkg/hash"
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/ecc/pkg/weierstrass"
	"github.com/primefactor-io/lindell17/pkg/dlenc_proof/messages"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/paillier/pkg/cipher"
	"github.com/primefactor-io/paillier/pkg/keys"
)

// Prover is an instance of a DLEnc proof prover.
type Prover struct {
	curve     weierstrass.Curve
	sk        *keys.PrivateKey
	x1        *big.Int
	alpha     *big.Int
	qHat      *elliptic.Point
	cRandVals *hash.Commitment
	state     lindell17.State
	outCh     chan<- lindell17.Message
	resCh     chan<- lindell17.Result
}

// NewProver creates a new instance of a DLEnc proof prover.
func NewProver(params *Params, outCh chan<- lindell17.Message, resCh chan<- lindell17.Result) *Prover {
	return &Prover{
		curve: params.curve,
		sk:    params.sk,
		x1:    params.x1,
		state: lindell17.Start,
		outCh: outCh,
		resCh: resCh,
	}
}

// Start starts the prover part of the protocol.
// Returns an error if the current state is invalid or starting the protocol
// fails.
func (p *Prover) Start() (bool, error) {
	// Validate state.
	if p.state != lindell17.Start {
		return false, lindell17.ErrInvalidState
	}

	// Transition to next state.
	p.state = lindell17.Step1

	return true, nil
}

// Process processes an incoming protocol message.
// Returns an error if the message was sent by the wrong sender, is invalid,
// unknown or not intended for the protocol / recipient.
func (p *Prover) Process(msg lindell17.Message) (bool, error) {
	// Check message protocol.
	if msg.Protocol() != lindell17.DLEncProof {
		return false, lindell17.ErrWrongProtocol
	}

	// Check message sender.
	if msg.From() != lindell17.Verifier {
		return false, lindell17.ErrWrongSender
	}

	// Check message recipient.
	if msg.To() != lindell17.Prover {
		return false, lindell17.ErrWrongRecipient
	}

	// Validate message.
	if !msg.IsValid() {
		return false, lindell17.ErrInvalidMessage
	}

	// Process message.
	switch msg.MessageId() {
	case 1:
		return p.step1(msg.(*messages.Message1))
	case 3:
		return p.step2(msg.(*messages.Message3))
	default:
		return false, lindell17.ErrUnknownMessage
	}
}

// step1 runs the prover's first step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Prover) step1(msg *messages.Message1) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if p.state != lindell17.Step1 {
		return false, lindell17.ErrInvalidState
	}

	// Decrypt ciphertext.
	plaintext, err := cipher.Decrypt(p.sk, msg.Ciphertext)
	if err != nil {
		return false, ErrDecryptCiphertext
	}

	// Turn decrypted result into big int to obtain alpha.
	alpha := new(big.Int).SetBytes(plaintext)

	// Compute Q^.
	qHat, err := p.curve.ScalarMultiply(alpha, p.curve.G()) // alpha * G
	if err != nil {
		return false, ErrComputeQHat
	}

	// Commit to Q^.
	cQHat, err := hash.Commit(qHat.X.Bytes(), qHat.Y.Bytes())
	if err != nil {
		return false, ErrCommitToQHat
	}

	// Store commitment to a and b.
	p.cRandVals = msg.CRandVals

	// Store alpha and Q^.
	p.alpha = alpha
	p.qHat = qHat

	// Transition to next state.
	p.state = lindell17.Step2

	// Send outbound message.
	p.outCh <- messages.NewMessage2(sid, cQHat)

	return true, nil
}

// step2 runs the prover's second step of the protocol and sends its result via
// the result channel.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Prover) step2(msg *messages.Message3) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if p.state != lindell17.Step2 {
		return false, lindell17.ErrInvalidState
	}

	// Verify commitment to a and b.
	isValid := hash.Verify(p.cRandVals, msg.A.Bytes(), msg.B.Bytes())

	// (Re)Compute alpha.
	in1 := new(big.Int).Mul(msg.A, p.x1)  // a * x1
	alpha := new(big.Int).Add(in1, msg.B) // (a * x1) + b

	// Check if alpha values match.
	isEqual := p.alpha.Cmp(alpha) == 0

	// Compute final result.
	result := isValid && isEqual

	// Fetch Q^.
	qHat := p.qHat

	// Send outbound message.
	p.outCh <- messages.NewMessage4(sid, qHat)

	// Send result.
	p.resCh <- NewResult(sid, result)

	return true, nil
}
