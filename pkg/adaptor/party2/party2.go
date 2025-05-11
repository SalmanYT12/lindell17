package party2

import (
	"crypto/rand"
	"math/big"

	"github.com/primefactor-io/commitment/pkg/hash"
	"github.com/primefactor-io/ecc/pkg/adaptor"
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/ecc/pkg/proofs"
	"github.com/primefactor-io/ecc/pkg/weierstrass"
	"github.com/primefactor-io/lindell17/pkg/adaptor/messages"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/lindell17/pkg/utils"
	"github.com/primefactor-io/paillier/pkg/cipher"
	"github.com/primefactor-io/paillier/pkg/homomorphic"
	"github.com/primefactor-io/paillier/pkg/keys"
)

// Party2 is an instance of party 2 that participates in the adaptor signature
// protocol.
type Party2 struct {
	curve   weierstrass.Curve
	pk      *keys.PublicKey
	qShared *elliptic.Point
	x1Enc   cipher.Ciphertext
	x2      *big.Int
	hash    []byte
	stmt    *adaptor.Statement
	pStmt   *proofs.DLKProof
	y       *elliptic.Point
	k2      *big.Int
	r2      *elliptic.Point
	r2Prime *elliptic.Point
	pR2     *proofs.DLKProof
	pK2DLEq *proofs.DLEqProof
	r1      *elliptic.Point
	state   lindell17.State
	outCh   chan<- lindell17.Message
	resCh   chan<- lindell17.Result
}

// NewParty2 creates a new instance of party 2 that participates in the adaptor
// signature protocol.
func NewParty2(params *Params, hash []byte, stmt *adaptor.Statement, pStmt *proofs.DLKProof, outCh chan<- lindell17.Message, resCh chan<- lindell17.Result) *Party2 {
	return &Party2{
		curve:   params.curve,
		pk:      params.pk,
		qShared: params.qShared,
		x1Enc:   params.x1Enc,
		x2:      params.x2,
		hash:    hash,
		stmt:    stmt,
		pStmt:   pStmt,
		state:   lindell17.Start,
		outCh:   outCh,
		resCh:   resCh,
	}
}

// Start starts party 2 of the protocol.
// Returns an error if the current state is invalid, the hash has an invalid
// length, the statement's DLK proof is invalid or starting the protocol fails.
func (p *Party2) Start() (bool, error) {
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

	// Run step 1.
	return p.step1(sid)
}

// Process processes an incoming protocol message.
// Returns an error if the message was sent by the wrong sender, is invalid,
// unknown or not intended for the protocol / recipient.
func (p *Party2) Process(msg lindell17.Message) (bool, error) {
	// Check message protocol.
	if msg.Protocol() != lindell17.Adaptor {
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
	case 2:
		return p.step2(msg.(*messages.Message2))
	case 4:
		return p.step3(msg.(*messages.Message4))
	default:
		return false, lindell17.ErrUnknownMessage
	}
}

// step1 runs party 2's first step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Party2) step1(sessionId string) (bool, error) {
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

	// Commit to R2.
	cR2, err := hash.Commit(r2.X.Bytes(), r2.Y.Bytes())
	if err != nil {
		return false, ErrCommitToR2
	}

	// Generate R2 DLK proof.
	pR2, err := proofs.GenerateDLKProof(p.curve, r2, k2)
	if err != nil {
		return false, ErrGenerateR2DLKProof
	}

	// Compute R2'.
	r2Prime, err := p.curve.ScalarMultiply(k2, p.y) // k2 * Y
	if err != nil {
		return false, ErrComputeR2Prime
	}

	// Commit to R2'.
	cR2Prime, err := hash.Commit(r2Prime.X.Bytes(), r2Prime.Y.Bytes())
	if err != nil {
		return false, ErrCommitToR2Prime
	}

	// Generate DLEq proof.
	pK2DLEq, err := proofs.GenerateDLEqProof(p.curve, p.curve.G(), r2, p.y, r2Prime, k2)
	if err != nil {
		return false, ErrGenerateDLEqProof
	}

	// Store k2, R2, R2', R2 DLK proof and DLEq proof.
	p.k2 = k2
	p.r2 = r2
	p.r2Prime = r2Prime
	p.pR2 = pR2
	p.pK2DLEq = pK2DLEq

	// Transition to next state.
	p.state = lindell17.Step2

	// Send outbound message.
	p.outCh <- messages.NewMessage1(sessionId, cR2, cR2Prime)

	return true, nil
}

// step2 runs party 2's second step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Party2) step2(msg *messages.Message2) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if p.state != lindell17.Step2 {
		return false, lindell17.ErrInvalidState
	}

	// Verify R1 DLK proof.
	isValid, err := proofs.VerifyDLKProof(p.curve, msg.PR1, msg.R1)
	if err != nil || !isValid {
		return false, ErrInvalidR1DLKProof
	}

	// Verify DLEq proof.
	isValid, err = proofs.VerifyDLEqProof(p.curve, msg.PK1DLEq, p.curve.G(), msg.R1, p.y, msg.R1Prime)
	if err != nil || !isValid {
		return false, ErrInvalidDLEqProof
	}

	// Compute R.
	rP, err := p.curve.ScalarMultiply(p.k2, msg.R1Prime) // k2 * R1' = k2 * (k1 * Y)
	if err != nil {
		return false, ErrComputeR
	}

	// Compute r.
	r := new(big.Int).Mod(rP.X, p.curve.N()) // R_x mod q

	// Turn hash into big integer.
	z := new(big.Int).SetBytes(p.hash)

	// Sample random p from Z_q^2.
	qq := new(big.Int).Mul(p.curve.N(), p.curve.N()) // q^2
	randP, err := rand.Int(rand.Reader, qq)
	if err != nil {
		return false, ErrSampleP
	}

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

	// Store R1.
	p.r1 = msg.R1

	// Transition to next state.
	p.state = lindell17.Step3

	// Send outbound message.
	p.outCh <- messages.NewMessage3(sid, p.r2, p.pR2, p.r2Prime, p.pK2DLEq, c3)

	return true, nil
}

// step3 runs party 2's third step of the protocol.
// Returns an error if the current state is invalid or the step can't be run
// properly.
func (p *Party2) step3(msg *messages.Message4) (bool, error) {
	sid := msg.SessionId()

	// Validate state.
	if p.state != lindell17.Step3 {
		return false, lindell17.ErrInvalidState
	}

	// Turn hash into big integer.
	z := new(big.Int).SetBytes(p.hash)

	// Invert s'.
	sPrimeInv := new(big.Int).ModInverse(msg.PreSig.S, p.curve.N()) // s'^-1 mod q

	// Compute u.
	in1 := new(big.Int).Mul(z, sPrimeInv)   // z * s'^-1
	u := new(big.Int).Mod(in1, p.curve.N()) // z * s'^-1 mod q

	// Compute v.
	in2 := new(big.Int).Mul(msg.PreSig.R, sPrimeInv) // r * s'^-1
	v := new(big.Int).Mod(in2, p.curve.N())          // r * s'^-1 mod q

	// Verify that k2 * R1 = (u * G) + (v * Q).
	lhs, err := p.curve.ScalarMultiply(p.k2, p.r1) // k2 * R1
	if err != nil {
		return false, ErrComputeK2TimesR1
	}
	in3, err := p.curve.ScalarMultiply(u, p.curve.G()) // u * G
	if err != nil {
		return false, ErrComputeUTimesG
	}
	in4, err := p.curve.ScalarMultiply(v, p.qShared) // v * Q
	if err != nil {
		return false, ErrComputeVTimesQ
	}
	rhs, err := p.curve.Add(in3, in4) // (u * G) + (v * Q)
	if err != nil {
		return false, ErrComputeUTimesGPlusVTimesQ
	}

	isValid := lhs.Equal(rhs)
	if !isValid {
		return false, ErrInvalidResult
	}

	// Send pre-signature over result channel.
	p.resCh <- NewResult(sid, msg.PreSig)

	return true, nil
}
