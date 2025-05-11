package party1

import (
	"math/big"

	"github.com/primefactor-io/commitment/pkg/hash"
	"github.com/primefactor-io/ecc/pkg/adaptor"
	"github.com/primefactor-io/ecc/pkg/ecdsa"
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/ecc/pkg/proofs"
	"github.com/primefactor-io/ecc/pkg/weierstrass"
	"github.com/primefactor-io/lindell17/pkg/adaptor/messages"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/lindell17/pkg/utils"
	"github.com/primefactor-io/paillier/pkg/cipher"
	"github.com/primefactor-io/paillier/pkg/keys"
)

// Party1 is an instance of party 1 that participates in the adaptor signature
// protocol.
type Party1 struct {
	curve    weierstrass.Curve
	sk       *keys.PrivateKey
	qShared  *elliptic.Point
	hash     []byte
	stmt     *adaptor.Statement
	pStmt    *proofs.DLKProof
	y        *elliptic.Point
	k1       *big.Int
	cR2      *hash.Commitment
	cR2Prime *hash.Commitment
	state    lindell17.State
	outCh    chan<- lindell17.Message
	resCh    chan<- lindell17.Result
}

// NewParty1 creates a new instance of party 1 that participates in the adaptor
// signature protocol.
func NewParty1(params *Params, hash []byte, stmt *adaptor.Statement, pStmt *proofs.DLKProof, outCh chan<- lindell17.Message, resCh chan<- lindell17.Result) *Party1 {
	return &Party1{
		curve:   params.curve,
		sk:      params.sk,
		qShared: params.qShared,
		hash:    hash,
		stmt:    stmt,
		pStmt:   pStmt,
		state:   lindell17.Start,
		outCh:   outCh,
		resCh:   resCh,
	}
}

// Start starts party 1 of the protocol.
// Returns an error if the current state is invalid, the hash has an invalid
// length, the statement's DLK proof is invalid or starting the protocol fails.
func (p *Party1) Start() (bool, error) {
	// Validate state.
	if p.state != lindell17.Start {
		return false, lindell17.ErrInvalidState
	}

	// Check if hash has length of 256 bits.
	if len(p.hash) != utils.HashLength {
		return false, ErrInvalidHashLength
	}

	// Verify Statement DLK proof.
	y := (*elliptic.Point)(p.stmt)
	isValid, err := proofs.VerifyDLKProof(p.curve, p.pStmt, y)
	if err != nil || !isValid {
		return false, ErrInvalidStatementDLKProof
	}

	// Store statement's underlying point.
	p.y = y

	// Transition to next state.
	p.state = lindell17.Step1

	return true, nil
}

// Process processes an incoming protocol message.
// Returns an error if the message was sent by the wrong sender, is invalid,
// unknown or not intended for the protocol / recipient.
func (p *Party1) Process(msg lindell17.Message) (bool, error) {
	// Check message protocol.
	if msg.Protocol() != lindell17.Adaptor {
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
	case 1:
		return p.step1(msg.(*messages.Message1))
	case 3:
		return p.step2(msg.(*messages.Message3))
	default:
		return false, lindell17.ErrUnknownMessage
	}
}

// step1 runs party 1's first step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Party1) step1(msg *messages.Message1) (bool, error) {
	sid := msg.SessionId()

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

	// Generate R1 DLK proof.
	pR1, err := proofs.GenerateDLKProof(p.curve, r1, k1)
	if err != nil {
		return false, ErrGenerateR1DLKProof
	}

	// Compute R1'.
	r1Prime, err := p.curve.ScalarMultiply(k1, p.y) // k1 * Y
	if err != nil {
		return false, ErrComputeR1Prime
	}

	// Generate DLEq proof.
	pK1DLEq, err := proofs.GenerateDLEqProof(p.curve, p.curve.G(), r1, p.y, r1Prime, k1)
	if err != nil {
		return false, ErrGenerateDLEqProof
	}

	// Store k1.
	p.k1 = k1

	// Store commitments to R2 and R2'.
	p.cR2 = msg.CR2
	p.cR2Prime = msg.CR2Prime

	// Transition to next state.
	p.state = lindell17.Step2

	// Send outbound message.
	p.outCh <- messages.NewMessage2(sid, r1, pR1, r1Prime, pK1DLEq)

	return true, nil
}

// step2 runs party 1's second step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Party1) step2(msg *messages.Message3) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if p.state != lindell17.Step2 {
		return false, lindell17.ErrInvalidState
	}

	// Verify commitment to R2.
	isValid := hash.Verify(p.cR2, msg.R2.X.Bytes(), msg.R2.Y.Bytes())
	if !isValid {
		return false, ErrInvalidR2Commitment
	}

	// Verify R2 DLK proof.
	isValid, err := proofs.VerifyDLKProof(p.curve, msg.PR2, msg.R2)
	if err != nil || !isValid {
		return false, ErrInvalidR2DLKProof
	}

	// Verify commitment to R2'.
	isValid = hash.Verify(p.cR2Prime, msg.R2Prime.X.Bytes(), msg.R2Prime.Y.Bytes())
	if !isValid {
		return false, ErrInvalidR2PrimeCommitment
	}

	// Verify DLEq proof.
	isValid, err = proofs.VerifyDLEqProof(p.curve, msg.PK2DLEq, p.curve.G(), msg.R2, p.y, msg.R2Prime)
	if err != nil || !isValid {
		return false, ErrInvalidDLEqProof
	}

	// Compute R.
	rP, err := p.curve.ScalarMultiply(p.k1, msg.R2Prime) // k1 * R2' = k1 * (k2 * Y)
	if err != nil {
		return false, ErrComputeR
	}

	// Compute r.
	r := new(big.Int).Mod(rP.X, p.curve.N()) // R_x mod q

	// Turn hash into big integer.
	z := new(big.Int).SetBytes(p.hash)

	// Compute s''.
	plaintext, err := cipher.Decrypt(p.sk, msg.Ciphertext)
	if err != nil {
		return false, ErrDecryptCiphertext
	}
	// Turn decrypted ciphertext into big int.
	sPPrime := new(big.Int).SetBytes(plaintext) // s''

	// Compute v.
	v := new(big.Int).And(rP.Y, big.NewInt(1)) // R_y & 1

	// Compute s'.
	in1 := new(big.Int).ModInverse(p.k1, p.curve.N()) // k1^-1 mod q
	in2 := new(big.Int).Mul(sPPrime, in1)             // s'' * k1^-1
	sPrime := new(big.Int).Mod(in2, p.curve.N())      // s'' * k1^-1 mod q

	// Invert s''.
	sPPrimeInv := new(big.Int).ModInverse(sPPrime, p.curve.N()) // s''^-1 mod q

	// Compute u_1.
	in3 := new(big.Int).Mul(z, sPPrimeInv)   // z * s''^-1
	u1 := new(big.Int).Mod(in3, p.curve.N()) // z * s''^-1 mod q

	// Compute u_2.
	in4 := new(big.Int).Mul(r, sPPrimeInv)   // r * s''^-1
	u2 := new(big.Int).Mod(in4, p.curve.N()) // r * s''^-1 mod q

	// Verify that R2 = (u_1 * G) + (u_2 * Q).
	lhs := msg.R2
	in5, err := p.curve.ScalarMultiply(u1, p.curve.G()) // u_1 * G
	if err != nil {
		return false, ErrComputeU1TimesG
	}
	in6, err := p.curve.ScalarMultiply(u2, p.qShared) // u_2 * Q
	if err != nil {
		return false, ErrComputeU2TimesQ
	}
	rhs, err := p.curve.Add(in5, in6) // (u_1 * G) + (u_2 * Q)
	if err != nil {
		return false, ErrComputeU1TimesGPlusU2TimesQ
	}

	isValid = lhs.Equal(rhs)
	if !isValid {
		return false, ErrInvalidResult
	}

	// Create pre-signature.
	preSignature := ecdsa.NewPreSignature(r, sPrime, v)

	// Send outbound message.
	p.outCh <- messages.NewMessage4(sid, preSignature)

	// Send pre-signature over result channel.
	p.resCh <- NewResult(sid, preSignature)

	return true, nil
}
