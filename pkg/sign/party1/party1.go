package party1

import (
	"math/big"

	"github.com/primefactor-io/commitment/pkg/hash"
	"github.com/primefactor-io/ecc/pkg/ecdsa"
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/ecc/pkg/keys"
	"github.com/primefactor-io/ecc/pkg/proofs"
	"github.com/primefactor-io/ecc/pkg/weierstrass"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/lindell17/pkg/sign/messages"
	"github.com/primefactor-io/lindell17/pkg/utils"
	"github.com/primefactor-io/paillier/pkg/cipher"
	pKeys "github.com/primefactor-io/paillier/pkg/keys"
)

// Party1 is an instance of party 1 that participates in the signing protocol.
type Party1 struct {
	curve   weierstrass.Curve
	sk      *pKeys.PrivateKey
	qShared *elliptic.Point
	hash    []byte
	k1      *big.Int
	r1      *elliptic.Point
	r2      *elliptic.Point
	state   lindell17.State
	outCh   chan<- lindell17.Message
	resCh   chan<- lindell17.Result
}

// NewParty1 creates a new instance of party 1 that participates in the signing
// protocol.
func NewParty1(params *Params, hash []byte, outCh chan<- lindell17.Message, resCh chan<- lindell17.Result) *Party1 {
	return &Party1{
		curve:   params.curve,
		sk:      params.sk,
		qShared: params.qShared,
		hash:    hash,
		state:   lindell17.Start,
		outCh:   outCh,
		resCh:   resCh,
	}
}

// Start starts party 1 of the protocol.
// Returns an error if the current state is invalid, the hash has an invalid
// length or starting the protocol fails.
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

	// Check if hash has length of 256 bits.
	if len(p.hash) != utils.HashLength {
		return false, ErrInvalidHashLength
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
	if msg.Protocol() != lindell17.Sign {
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

	// Sample random partial nonce k1.
	k1, err := p.curve.GetRandomScalar()
	if err != nil {
		return false, ErrSampleNonceK1
	}

	// Compute R1.
	r1, err := p.curve.ScalarMultiply(k1, p.curve.G()) // k1 * G
	if err != nil {
		return false, ErrComputeR1
	}

	// Commit to R1.
	cR1, err := hash.Commit(r1.X.Bytes(), r1.Y.Bytes())
	if err != nil {
		return false, ErrCommitToR1
	}

	// Generate R1 DLK proof.
	pR1, err := proofs.GenerateDLKProof(p.curve, r1, k1)
	if err != nil {
		return false, ErrGenerateR1DLKProof
	}

	// Store k1 and R1.
	p.k1 = k1
	p.r1 = r1

	// Transition to next state.
	p.state = lindell17.Step2

	// Send outbound message.
	p.outCh <- messages.NewMessage1(sessionId, cR1, pR1)

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

	// Verify R2 DLK proof.
	isValid, err := proofs.VerifyDLKProof(p.curve, msg.PR2, msg.R2)
	if err != nil || !isValid {
		return false, ErrInvalidR2DLKProof
	}

	// Fetch R1.
	r1 := p.r1

	// Store R2.
	p.r2 = msg.R2

	// Transition to next state.
	p.state = lindell17.Step3

	// Send outbound message.
	p.outCh <- messages.NewMessage3(sid, r1)

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

	// Derive shared point R.
	rP, err := p.curve.ScalarMultiply(p.k1, p.r2) // k1 * R2
	if err != nil {
		return false, ErrComputeR
	}

	// Compute r.
	r := new(big.Int).Mod(rP.X, p.curve.N()) // R_x mod q

	// Check if r of partial signature equals r.
	if msg.R.Cmp(r) != 0 {
		return false, ErrInvalidR
	}

	// Compute s.
	sPrime, err := cipher.Decrypt(p.sk, msg.Ciphertext)
	if err != nil {
		return false, ErrDecryptCiphertext
	}

	// Compute v.
	v := new(big.Int).And(rP.Y, big.NewInt(1)) // R_y & 1

	// Turn decrypted ciphertext into big int.
	in1 := new(big.Int).SetBytes(sPrime)              // s'
	in2 := new(big.Int).ModInverse(p.k1, p.curve.N()) // k1^-1 mod q
	in3 := new(big.Int).Mul(in1, in2)                 // s' * k1^-1
	s1 := new(big.Int).Mod(in3, p.curve.N())          // s' * k1^-1 mod q
	s2 := new(big.Int).Sub(p.curve.N(), s1)           // q - (s' * k1^-1 mod q)

	// s = min(s1, s2).
	// Ensures that s is always smaller than half of the curve.
	s := s1
	if s2.Cmp(s1) < 0 {
		s = s2

		// Invert v.
		v = v.Xor(v, big.NewInt(1)) // v ^ 1
	}

	// Create signature.
	signature := ecdsa.NewSignature(r, s, v)

	// Verify signature.
	pk := (*keys.PublicKey)(p.qShared)
	isValid, err := ecdsa.Verify(p.curve, pk, p.hash, signature)
	if err != nil || !isValid {
		return false, ErrInvalidSignature
	}

	// Send signature over result channel.
	p.resCh <- NewResult(sid, signature)

	return true, nil
}
