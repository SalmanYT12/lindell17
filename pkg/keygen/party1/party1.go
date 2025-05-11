package party1

import (
	"math/big"

	"github.com/primefactor-io/commitment/pkg/hash"
	"github.com/primefactor-io/ecc/pkg/elliptic"
	sProofs "github.com/primefactor-io/ecc/pkg/proofs"
	"github.com/primefactor-io/ecc/pkg/weierstrass"
	dlencproof "github.com/primefactor-io/lindell17/pkg/dlenc_proof/messages"
	"github.com/primefactor-io/lindell17/pkg/dlenc_proof/prover"
	"github.com/primefactor-io/lindell17/pkg/keygen/messages"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/lindell17/pkg/utils"
	"github.com/primefactor-io/paillier/pkg/cipher"
	"github.com/primefactor-io/paillier/pkg/keys"
	pProofs "github.com/primefactor-io/paillier/pkg/proofs"
)

// Party1 is an instance of party 1 that participates in the key generation
// protocol.
type Party1 struct {
	curve            weierstrass.Curve
	rangeProofBits   int
	nthRootProofBits int
	paillierBits     int
	x1               *big.Int
	q1               *elliptic.Point
	q2               *elliptic.Point
	sk               *keys.PrivateKey
	pk               *keys.PublicKey
	prover           *prover.Prover
	proverOutCh      chan lindell17.Message
	proverResCh      chan lindell17.Result
	state            lindell17.State
	outCh            chan<- lindell17.Message
	resCh            chan<- lindell17.Result
}

// NewParty1 creates a new instance of party 1 that participates in the key
// generation protocol.
func NewParty1(params *Params, outCh chan<- lindell17.Message, resCh chan<- lindell17.Result) *Party1 {
	return &Party1{
		curve:            params.curve,
		rangeProofBits:   params.rangeProofBits,
		nthRootProofBits: params.nthRootProofBits,
		paillierBits:     params.paillierBits,
		state:            lindell17.Start,
		outCh:            outCh,
		resCh:            resCh,
	}
}

// Start starts party 1 of the protocol.
// Returns an error if the current state is invalid or starting the protocol
// fails.
func (p *Party1) Start() (bool, error) {
	// Validate state.
	if p.state != lindell17.Start {
		return false, lindell17.ErrInvalidState
	}

	// Generate session id.
	bits := 128
	sid, err := utils.GenerateSessionId(bits)
	if err != nil {
		return false, lindell17.ErrGenerateSessionId
	}

	// Transition to next state.
	p.state = lindell17.Step1

	// Run step 1.
	return p.step1(sid)
}

// Process processes an incoming protocol message.
// Returns an error if the message was sent by the wrong sender, is invalid,
// unknown or not intended for the protocol / recipient.
func (p *Party1) Process(msg lindell17.Message) (bool, error) {
	// Check message protocol.
	if msg.Protocol() != lindell17.Keygen {
		return false, lindell17.ErrWrongProtocol
	}

	// Check message sender.
	if msg.From() != lindell17.Party2 {
		return false, lindell17.ErrWrongSender
	}

	// Check message recipient.
	if msg.To() != lindell17.Party1 {
		return false, lindell17.ErrWrongRecipient
	}

	// Validate message.
	if !msg.IsValid() {
		return false, lindell17.ErrInvalidMessage
	}

	// Process message.
	switch msg.MessageId() {
	case 2:
		return p.step2(msg.(*messages.Message2))
	case 4:
		return p.step3(msg.(*messages.Message4))
	case 6:
		return p.step4(msg.(*messages.Message6))
	default:
		return false, lindell17.ErrUnknownMessage
	}
}

// step1 runs party 1's first step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Party1) step1(sessionId string) (bool, error) {
	// Validate state.
	if p.state != lindell17.Step1 {
		return false, lindell17.ErrInvalidState
	}

	// x1 should be in the range x1 >= 0 and x1 < q / 3.
	q3 := new(big.Int).Div(p.curve.N(), big.NewInt(3)) // q / 3

	// Sample the random scalar x1.
	x1, err := p.curve.GetRandomScalar(q3)
	if err != nil {
		return false, ErrSampleScalarX1
	}

	// Compute Q1 by multiplying x1 with the curve's generator.
	q1, err := p.curve.ScalarMultiply(x1, p.curve.G()) // x1 * G
	if err != nil {
		return false, ErrComputeQ1
	}

	// Commit to Q1.
	cQ1, err := hash.Commit(q1.X.Bytes(), q1.Y.Bytes())
	if err != nil {
		return false, ErrCommitToQ1
	}

	// Generate Q1 DLK proof.
	pQ1, err := sProofs.GenerateDLKProof(p.curve, q1, x1)
	if err != nil {
		return false, ErrGenerateQ1DLKProof
	}

	// Store x1 and Q1.
	p.x1 = x1
	p.q1 = q1

	// Transition to next state.
	p.state = lindell17.Step2

	// Send outbound message.
	p.outCh <- messages.NewMessage1(sessionId, cQ1, pQ1)

	return true, nil
}

// step2 runs party 1's second step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Party1) step2(msg *messages.Message2) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if p.state != lindell17.Step2 {
		return false, lindell17.ErrInvalidState
	}

	// Verify Q2 DLK proof.
	isValid, err := sProofs.VerifyDLKProof(p.curve, msg.PQ2, msg.Q2)
	if err != nil || !isValid {
		return false, ErrInvalidQ2DLKProof
	}

	// Fetch Q1.
	q1 := p.q1

	// Generate Paillier keys.
	sk, pk, err := keys.GenerateKeys(p.paillierBits)
	if err != nil {
		return false, ErrGeneratePaillierKeys
	}

	// Generate Nth root proof.
	pNthRoot, err := pProofs.GenerateNthRootProof(p.nthRootProofBits, pk.N)
	if err != nil {
		return false, ErrGenerateNthRootProof
	}

	// Encrypt x1.
	x1Enc, r, err := cipher.EncryptAndReturnNonce(pk, p.x1.Bytes())
	if err != nil {
		return false, ErrEncryptX1
	}

	//  Generate range proof.
	pRange, err := pProofs.GenerateRangeProof(p.rangeProofBits, pk, p.curve.N(), p.x1, r)
	if err != nil {
		return false, ErrGenerateRangeProof
	}

	// Initialize and start DLEnc proof prover.
	p.proverOutCh = make(chan lindell17.Message, 1)
	p.proverResCh = make(chan lindell17.Result, 1)
	params := prover.NewParams(p.curve, sk, p.x1)
	p.prover = prover.NewProver(params, p.proverOutCh, p.proverResCh)
	ok, err := p.prover.Start()
	if !ok || err != nil {
		return false, ErrInitializeDLEncProofProver
	}

	// Store Q2.
	p.q2 = msg.Q2

	// Store sk and pk.
	p.sk = sk
	p.pk = pk

	// Transition to next state.
	p.state = lindell17.Step3

	// Send outbound message.
	p.outCh <- messages.NewMessage3(sid, q1, pk, pNthRoot, x1Enc, pRange)

	return true, nil
}

// step3 runs party 1's third step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Party1) step3(msg *messages.Message4) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if p.state != lindell17.Step3 {
		return false, lindell17.ErrInvalidState
	}

	// Process incoming message.
	ok, err := p.prover.Process(&msg.Message1)
	if !ok || err != nil {
		return false, ErrProcessDLEncProofMessage1
	}

	// Read prover message.
	message := <-p.proverOutCh

	// Transition to next state.
	p.state = lindell17.Step4

	// Send outbound message.
	p.outCh <- messages.NewMessage5(sid, message.(*dlencproof.Message2))

	return true, nil
}

// step4 runs party 1's fourth step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Party1) step4(msg *messages.Message6) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if p.state != lindell17.Step4 {
		return false, lindell17.ErrInvalidState
	}

	// Process incoming message.
	ok, err := p.prover.Process(&msg.Message3)
	if !ok || err != nil {
		return false, ErrProcessDLEncProofMessage3
	}

	// Read prover message.
	message := <-p.proverOutCh

	// Send outbound message.
	p.outCh <- messages.NewMessage7(sid, message.(*dlencproof.Message4))

	// Read prover result.
	res := <-p.proverResCh
	result := res.(*prover.Result)

	if !result.IsValid {
		return false, ErrInvalidDLEncProof
	}

	// Compute Q by multiplying x1 with Q2.
	q, err := p.curve.ScalarMultiply(p.x1, p.q2) // x1 * Q2
	if err != nil {
		return false, ErrComputeQ
	}

	// Create key material.
	keyMaterial := NewKeyMaterial(p.x1, p.sk, p.pk, q)

	// Send key material over result channel.
	p.resCh <- NewResult(sid, keyMaterial)

	return true, nil
}
