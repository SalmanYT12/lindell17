package party2

import (
	"math/big"

	"github.com/primefactor-io/commitment/pkg/hash"
	"github.com/primefactor-io/ecc/pkg/elliptic"
	sProofs "github.com/primefactor-io/ecc/pkg/proofs"
	"github.com/primefactor-io/ecc/pkg/weierstrass"
	dlencproof "github.com/primefactor-io/lindell17/pkg/dlenc_proof/messages"
	"github.com/primefactor-io/lindell17/pkg/dlenc_proof/verifier"
	"github.com/primefactor-io/lindell17/pkg/keygen/messages"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/paillier/pkg/cipher"
	"github.com/primefactor-io/paillier/pkg/keys"
	pProofs "github.com/primefactor-io/paillier/pkg/proofs"
)

// Party2 is an instance of party 2 that participates in the key generation
// protocol.
type Party2 struct {
	curve            weierstrass.Curve
	rangeProofBits   int
	nthRootProofBits int
	cQ1              *hash.Commitment
	pQ1              *sProofs.DLKProof
	x1Enc            cipher.Ciphertext
	q1               *elliptic.Point
	x2               *big.Int
	q2               *elliptic.Point
	pk               *keys.PublicKey
	verifier         *verifier.Verifier
	verifierOutCh    chan lindell17.Message
	verifierResCh    chan lindell17.Result
	state            lindell17.State
	outCh            chan<- lindell17.Message
	resCh            chan<- lindell17.Result
}

// NewParty2 creates a new instance of party 2 that participates in the key
// generation protocol.
func NewParty2(params *Params, outCh chan<- lindell17.Message, resCh chan<- lindell17.Result) *Party2 {
	return &Party2{
		curve:            params.curve,
		rangeProofBits:   params.rangeProofBits,
		nthRootProofBits: params.nthRootProofBits,
		state:            lindell17.Start,
		outCh:            outCh,
		resCh:            resCh,
	}
}

// Start starts party 2 of the protocol.
// Returns an error if the current state is invalid or starting the protocol
// fails.
func (p *Party2) Start() (bool, error) {
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
func (p *Party2) Process(msg lindell17.Message) (bool, error) {
	// Check message protocol.
	if msg.Protocol() != lindell17.Keygen {
		return false, lindell17.ErrWrongProtocol
	}

	// Check message sender.
	if msg.From() != lindell17.Party1 {
		return false, lindell17.ErrWrongSender
	}

	// Check message recipient.
	if msg.To() != lindell17.Party2 {
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
	case 5:
		return p.step3(msg.(*messages.Message5))
	case 7:
		return p.step4(msg.(*messages.Message7))
	default:
		return false, lindell17.ErrUnknownMessage
	}
}

// step1 runs party 2's first step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Party2) step1(msg *messages.Message1) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if p.state != lindell17.Step1 {
		return false, lindell17.ErrInvalidState
	}

	// Sample the random scalar x2.
	x2, err := p.curve.GetRandomScalar()
	if err != nil {
		return false, ErrSampleScalarX2
	}

	// Compute Q2 by multiplying x2 with the curve's generator.
	q2, err := p.curve.ScalarMultiply(x2, p.curve.G()) // x2 * G
	if err != nil {
		return false, ErrComputeQ2
	}

	// Generate Q2 DLK proof.
	pQ2, err := sProofs.GenerateDLKProof(p.curve, q2, x2)
	if err != nil {
		return false, ErrGenerateQ2DLKProof
	}

	// Store commitment to Q1 and Q1 DLK proof.
	p.cQ1 = msg.CQ1
	p.pQ1 = msg.PQ1

	// Store x2 and Q2.
	p.x2 = x2
	p.q2 = q2

	// Transition to next state.
	p.state = lindell17.Step2

	// Send outbound message.
	p.outCh <- messages.NewMessage2(sid, q2, pQ2)

	return true, nil
}

// step2 runs party 2's second step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Party2) step2(msg *messages.Message3) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if p.state != lindell17.Step2 {
		return false, lindell17.ErrInvalidState
	}

	// Verify commitment to Q1.
	isValid := hash.Verify(p.cQ1, msg.Q1.X.Bytes(), msg.Q1.Y.Bytes())
	if !isValid {
		return false, ErrInvalidQ1Commitment
	}

	// Verify Q1 DLK proof.
	isValid, err := sProofs.VerifyDLKProof(p.curve, p.pQ1, msg.Q1)
	if err != nil || !isValid {
		return false, ErrInvalidQ1DLKProof
	}

	// Verify Nth root proof.
	isValid, err = pProofs.VerifyNthRootProof(msg.PNthRoot, p.nthRootProofBits, msg.Pk.N)
	if err != nil || !isValid {
		return false, ErrInvalidNthRootProof
	}

	// Verify range proof.
	isValid, err = pProofs.VerifyRangeProof(msg.PRange, p.rangeProofBits, msg.Pk, p.curve.N(), msg.X1Enc)
	if err != nil || !isValid {
		return false, ErrInvalidRangeProof
	}

	// Initialize and start DLEnc proof verifier.
	p.verifierOutCh = make(chan lindell17.Message, 1)
	p.verifierResCh = make(chan lindell17.Result, 1)
	params := verifier.NewParams(p.curve, msg.Q1, msg.Pk, msg.X1Enc)
	p.verifier = verifier.NewVerifier(params, p.verifierOutCh, p.verifierResCh)
	ok, err := p.verifier.Start()
	if !ok || err != nil {
		return false, ErrInitializeDLEncProofVerifier
	}

	// Store Q1, pk and x1Enc.
	p.q1 = msg.Q1
	p.pk = msg.Pk
	p.x1Enc = msg.X1Enc

	// Read verifier message.
	message := <-p.verifierOutCh

	// Transition to next state.
	p.state = lindell17.Step3

	// Send outbound message.
	p.outCh <- messages.NewMessage4(sid, message.(*dlencproof.Message1))

	return true, nil
}

// step3 runs party 2's third step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Party2) step3(msg *messages.Message5) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if p.state != lindell17.Step3 {
		return false, lindell17.ErrInvalidState
	}

	// Process incoming message.
	ok, err := p.verifier.Process(&msg.Message2)
	if !ok || err != nil {
		return false, ErrProcessDLEncProofMessage2
	}

	// Read verifier message.
	message := <-p.verifierOutCh

	// Transition to next state.
	p.state = lindell17.Step4

	// Send outbound message.
	p.outCh <- messages.NewMessage6(sid, message.(*dlencproof.Message3))

	return true, nil
}

// step4 runs party 2's fourth step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Party2) step4(msg *messages.Message7) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if p.state != lindell17.Step4 {
		return false, lindell17.ErrInvalidState
	}

	// Process incoming message.
	ok, err := p.verifier.Process(&msg.Message4)
	if !ok || err != nil {
		return false, ErrProcessDLEncProofMessage4
	}

	// Read verifier result.
	res := <-p.verifierResCh
	result := res.(*verifier.Result)

	if !result.IsValid {
		return false, ErrInvalidDLEncProof
	}

	// Compute Q by multiplying x2 with Q1.
	q, err := p.curve.ScalarMultiply(p.x2, p.q1) // x2 * Q1
	if err != nil {
		return false, ErrComputeQ
	}

	// Create key material.
	keyMaterial := NewKeyMaterial(p.x1Enc, p.x2, p.pk, q)

	// Send key material over result channel.
	p.resCh <- NewResult(sid, keyMaterial)

	return true, nil
}
