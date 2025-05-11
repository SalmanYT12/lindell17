package party2

import (
	"crypto/rand"
	"math/big"

	"github.com/primefactor-io/commitment/pkg/hash"
	"github.com/primefactor-io/ecc/pkg/proofs"
	"github.com/primefactor-io/ecc/pkg/weierstrass"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/lindell17/pkg/sign/messages"
	"github.com/primefactor-io/lindell17/pkg/utils"
	"github.com/primefactor-io/paillier/pkg/cipher"
	"github.com/primefactor-io/paillier/pkg/homomorphic"
	"github.com/primefactor-io/paillier/pkg/keys"
)

// Party2 is an instance of party 2 that participates in the signing protocol.
type Party2 struct {
	curve weierstrass.Curve
	pk    *keys.PublicKey
	x1Enc cipher.Ciphertext
	x2    *big.Int
	hash  []byte
	k2    *big.Int
	cR1   *hash.Commitment
	pR1   *proofs.DLKProof
	state lindell17.State
	outCh chan<- lindell17.Message
	resCh chan<- lindell17.Result
}

// NewParty2 creates a new instance of party 2 that participates in the signing
// protocol.
func NewParty2(params *Params, hash []byte, outCh chan<- lindell17.Message, resCh chan<- lindell17.Result) *Party2 {
	return &Party2{
		curve: params.curve,
		pk:    params.pk,
		x1Enc: params.x1Enc,
		x2:    params.x2,
		hash:  hash,
		state: lindell17.Start,
		outCh: outCh,
		resCh: resCh,
	}
}

// Start starts party 2 of the protocol.
// Returns an error if the current state is invalid, the hash has an invalid
// length or starting the protocol fails.
func (p *Party2) Start() (bool, error) {
	// Validate state.
	if p.state != lindell17.Start {
		return false, lindell17.ErrInvalidState
	}

	// Check if hash has length of 256 bits.
	if len(p.hash) != utils.HashLength {
		return false, ErrInvalidHashLength
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
	if msg.Protocol() != lindell17.Sign {
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

	// Sample random partial nonce k2.
	k2, err := p.curve.GetRandomScalar()
	if err != nil {
		return false, ErrSampleNonceK2
	}

	// Compute R2.
	r2, err := p.curve.ScalarMultiply(k2, p.curve.G()) // k2 * G
	if err != nil {
		return false, ErrComputeR2
	}

	// Generate R2 DLK proof.
	pR2, err := proofs.GenerateDLKProof(p.curve, r2, k2)
	if err != nil {
		return false, ErrGenerateR2DLKProof
	}

	// Store commitment to R1 and R1 DLK proof.
	p.cR1 = msg.CR1
	p.pR1 = msg.PR1

	// Store k2.
	p.k2 = k2

	// Transition to next state.
	p.state = lindell17.Step2

	// Send outbound message.
	p.outCh <- messages.NewMessage2(sid, r2, pR2)

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

	// Verify commitment to R1.
	isValid := hash.Verify(p.cR1, msg.R1.X.Bytes(), msg.R1.Y.Bytes())
	if !isValid {
		return false, ErrInvalidR1Commitment
	}

	// Verify R1 DLK proof.
	isValid, err := proofs.VerifyDLKProof(p.curve, p.pR1, msg.R1)
	if err != nil || !isValid {
		return false, ErrInvalidR1DLKProof
	}

	// Derive shared point R.
	rP, err := p.curve.ScalarMultiply(p.k2, msg.R1) // k2 * R1
	if err != nil {
		return false, ErrComputeR
	}

	// Compute r.
	r := new(big.Int).Mod(rP.X, p.curve.N()) // R_x mod q

	// Sample random p from Z_q^2.
	qq := new(big.Int).Mul(p.curve.N(), p.curve.N()) // q^2
	randP, err := rand.Int(rand.Reader, qq)
	if err != nil {
		return false, ErrSampleP
	}

	// Turn hash into big integer.
	z := new(big.Int).SetBytes(p.hash)

	// Invert k2.
	k2Inv := new(big.Int).ModInverse(p.k2, p.curve.N()) // k2^-1 mod q

	// Compute c1.
	in1 := new(big.Int).Mul(z, k2Inv)           // z * k2^-1
	in2 := new(big.Int).Mod(in1, p.curve.N())   // z * k2^-1 mod q
	in3 := new(big.Int).Mul(randP, p.curve.N()) // p * q
	res := new(big.Int).Add(in2, in3)           // (z * k2^-1 mod q) + (p * q)
	c1, nonce, err := cipher.EncryptAndReturnNonce(p.pk, res.Bytes())
	if err != nil {
		return false, ErrComputeC1
	}

	// Ensure that gcd(nonce, N) = 1.
	gcd, _, _ := utils.ExtendedEuclidean(nonce, p.pk.N)
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return false, ErrInvalidGCD
	}

	// Compute v.
	in4 := new(big.Int).Mul(r, k2Inv)       // r * k2^-1
	in5 := new(big.Int).Mul(in4, p.x2)      // r * k2^-1 * x2
	v := new(big.Int).Mod(in5, p.curve.N()) // r * k2^-1 * x2 mod q

	// Compute c2.
	c2, err := homomorphic.MultiplyPlaintextValue(p.pk, p.x1Enc, v.Bytes())
	if err != nil {
		return false, ErrComputeC2
	}

	// Compute c3.
	c3 := homomorphic.AddPlaintextValues(p.pk, c1, c2)

	// Send outbound message.
	p.outCh <- messages.NewMessage4(sid, r, c3)

	// Send partial signature over result channel.
	p.resCh <- NewResult(sid, r, c3)

	return true, nil
}
