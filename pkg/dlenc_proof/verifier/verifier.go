package verifier

import (
	"crypto/rand"
	"math/big"

	"github.com/primefactor-io/commitment/pkg/hash"
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/ecc/pkg/weierstrass"
	"github.com/primefactor-io/lindell17/pkg/dlenc_proof/messages"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/lindell17/pkg/utils"
	"github.com/primefactor-io/paillier/pkg/cipher"
	"github.com/primefactor-io/paillier/pkg/homomorphic"
	"github.com/primefactor-io/paillier/pkg/keys"
)

// Verifier is an instance of a DLEnc proof verifier.
type Verifier struct {
	curve weierstrass.Curve
	q1    *elliptic.Point
	pk    *keys.PublicKey
	x1Enc cipher.Ciphertext
	a     *big.Int
	b     *big.Int
	cQHat *hash.Commitment
	state lindell17.State
	outCh chan<- lindell17.Message
	resCh chan<- lindell17.Result
}

// NewVerifier creates a new instance of a DLEnc proof verifier.
func NewVerifier(params *Params, outCh chan<- lindell17.Message, resCh chan<- lindell17.Result) *Verifier {
	return &Verifier{
		curve: params.curve,
		q1:    params.q1,
		pk:    params.pk,
		x1Enc: params.x1Enc,
		state: lindell17.Start,
		outCh: outCh,
		resCh: resCh,
	}
}

// Start starts the verifier part of the protocol.
// Returns an error if the current state is invalid or starting the protocol
// fails.
func (v *Verifier) Start() (bool, error) {
	// Validate state.
	if v.state != lindell17.Start {
		return false, lindell17.ErrInvalidState
	}

	// Generate session id.
	bits := 128
	sid, err := utils.GenerateSessionId(bits)
	if err != nil {
		return false, lindell17.ErrGenerateSessionId
	}

	// Transition to next state.
	v.state = lindell17.Step1

	// Run step 1.
	return v.step1(sid)
}

// Process processes an incoming protocol message.
// Returns an error if the message was sent by the wrong sender, is invalid,
// unknown or not intended for the protocol / recipient.
func (v *Verifier) Process(msg lindell17.Message) (bool, error) {
	// Check message protocol.
	if msg.Protocol() != lindell17.DLEncProof {
		return false, lindell17.ErrWrongProtocol
	}

	// Check message sender.
	if msg.From() != lindell17.Prover {
		return false, lindell17.ErrWrongSender
	}

	// Check message recipient.
	if msg.To() != lindell17.Verifier {
		return false, lindell17.ErrWrongRecipient
	}

	// Validate message.
	if !msg.IsValid() {
		return false, lindell17.ErrInvalidMessage
	}

	// Process message.
	switch msg.MessageId() {
	case 2:
		return v.step2(msg.(*messages.Message2))
	case 4:
		return v.step3(msg.(*messages.Message4))
	default:
		return false, lindell17.ErrUnknownMessage
	}
}

// step1 runs the verifier's first step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (v *Verifier) step1(sessionId string) (bool, error) {
	// Validate state.
	if v.state != lindell17.Step1 {
		return false, lindell17.ErrInvalidState
	}

	qq := new(big.Int).Mul(v.curve.N(), v.curve.N()) // q^2

	// Sample random a from Z_q.
	a, err := rand.Int(rand.Reader, v.curve.N())
	if err != nil {
		return false, ErrSampleA
	}

	// Sample random b from Z_q^2.
	b, err := rand.Int(rand.Reader, qq)
	if err != nil {
		return false, ErrSampleB
	}

	// Commit to a and b.
	cRandVals, err := hash.Commit(a.Bytes(), b.Bytes())
	if err != nil {
		return false, ErrCommitToAAndB
	}

	// Encrypt b.
	in1, r, err := cipher.EncryptAndReturnNonce(v.pk, b.Bytes())
	if err != nil {
		return false, ErrEncryptB
	}

	// Ensure that gcd(r, N) = 1.
	gcd, _, _ := utils.ExtendedEuclidean(r, v.pk.N)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return false, ErrInvalidGCD
	}

	// Multiply plaintext of x1Enc (which is the discrete logarithm x1) with a.
	in2, err := homomorphic.MultiplyPlaintextValue(v.pk, v.x1Enc, a.Bytes())
	if err != nil {
		return false, ErrMultiplyPlaintextValue
	}

	// Add the two underlying plaintext values.
	ciphertext := homomorphic.AddPlaintextValues(v.pk, in1, in2)

	// Store a and b.
	v.a = a
	v.b = b

	// Transition to next state.
	v.state = lindell17.Step2

	// Send outbound message.
	v.outCh <- messages.NewMessage1(sessionId, cRandVals, ciphertext)

	return true, nil
}

// step2 runs the verifier's second step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (v *Verifier) step2(msg *messages.Message2) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if v.state != lindell17.Step2 {
		return false, lindell17.ErrInvalidState
	}

	// Store Q^ commitment.
	v.cQHat = msg.CQHat

	// Fetch values a and b.
	a := v.a
	b := v.b

	// Transition to next state.
	v.state = lindell17.Step3

	// Send outbound message.
	v.outCh <- messages.NewMessage3(sid, a, b)

	return true, nil
}

// step3 runs the verifier's third step of the protocol and sends its result
// via the result channel.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (v *Verifier) step3(msg *messages.Message4) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if v.state != lindell17.Step3 {
		return false, lindell17.ErrInvalidState
	}

	// Verify commitment to Q^.
	isValid := hash.Verify(v.cQHat, msg.QHat.X.Bytes(), msg.QHat.Y.Bytes())

	// Compute Q'.
	in1, err := v.curve.ScalarMultiply(v.a, v.q1) // a * Q1
	if err != nil {
		return false, ErrComputeATimesQ1
	}
	in2, err := v.curve.ScalarMultiply(v.b, v.curve.G()) // b * G
	if err != nil {
		return false, ErrComputeBTimesG
	}
	qPrime, err := v.curve.Add(in1, in2) // (a * Q1) + (b * G)
	if err != nil {
		return false, ErrComputeATimesQ1PlusBTimesG
	}

	// Check if Q^ equals Q'.
	isEqual := msg.QHat.Equal(qPrime)

	// Compute final result.
	result := isValid && isEqual

	// Send result.
	v.resCh <- NewResult(sid, result)

	return true, nil
}
