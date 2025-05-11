package adaptor_test

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/primefactor-io/ecc/pkg/adaptor"
	"github.com/primefactor-io/ecc/pkg/curves"
	"github.com/primefactor-io/ecc/pkg/ecdsa"
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/ecc/pkg/keys"
	"github.com/primefactor-io/ecc/pkg/proofs"
	"github.com/primefactor-io/lindell17/pkg/adaptor/party1"
	"github.com/primefactor-io/lindell17/pkg/adaptor/party2"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/paillier/pkg/cipher"
	pKeys "github.com/primefactor-io/paillier/pkg/keys"
)

var p1Params *party1.Params
var p2Params *party2.Params
var qShared *elliptic.Point
var wit *adaptor.Witness
var stmt *adaptor.Statement
var pStmt *proofs.DLKProof

var secp256k1 = curves.Secp256k1

func TestMain(m *testing.M) {
	// x1 should be in the range x1 >= 0 and x1 < q / 3.
	q3 := new(big.Int).Div(secp256k1.N(), big.NewInt(3)) // q / 3

	wit, stmt, _ = adaptor.GenerateHardRelation(secp256k1)
	pStmt, _ = proofs.GenerateDLKProof(secp256k1, (*elliptic.Point)(stmt), (*big.Int)(wit))

	sk, pk, _ := pKeys.GenerateKeys(1024)

	x1, _ := secp256k1.GetRandomScalar(q3)
	x1Enc, _ := cipher.Encrypt(pk, x1.Bytes())

	x2, _ := secp256k1.GetRandomScalar()
	q2, _ := secp256k1.ScalarMultiply(x2, secp256k1.G())

	// Note that x1 * Q2 = x2 * Q1.
	qShared, _ = secp256k1.ScalarMultiply(x1, q2)

	p1Params = party1.NewParams(secp256k1, sk, qShared)
	p2Params = party2.NewParams(secp256k1, pk, qShared, x1Enc, x2)

	m.Run()
}

func TestAdaptor(t *testing.T) {
	t.Parallel()

	t.Run("Sign / Verify / Public Key Recovery (valid)", func(t *testing.T) {
		t.Parallel()

		errCh := make(chan error, 2)
		outCh := make(chan lindell17.Message, 2)
		resCh := make(chan lindell17.Result, 2)

		message := []byte("Hello World")
		checksum := sha256.Sum256(message)
		hash := checksum[:]

		p1 := party1.NewParty1(p1Params, hash, stmt, pStmt, outCh, resCh)
		p2 := party2.NewParty2(p2Params, hash, stmt, pStmt, outCh, resCh)

		if _, err := p1.Start(); err != nil {
			errCh <- err
		}

		if _, err := p2.Start(); err != nil {
			errCh <- err
		}

		var counter int32
		c := newContainer()

	coord:
		for {
			select {
			case msg := <-outCh:
				switch msg.To() {
				case lindell17.Party1:
					if _, err := p1.Process(msg); err != nil {
						errCh <- err
					}
				case lindell17.Party2:
					if _, err := p2.Process(msg); err != nil {
						errCh <- err
					}
				}
			case err := <-errCh:
				t.Fatalf("expected no error, got %v", err)
			case result := <-resCh:
				atomic.AddInt32(&counter, 1)

				switch result.From() {
				case lindell17.Party1:
					res := result.(*party1.Result)
					c.add(result.From(), res.PreSignature)
				case lindell17.Party2:
					res := result.(*party2.Result)
					c.add(result.From(), res.PreSignature)
				}

				if atomic.LoadInt32(&counter) == 2 {
					p1PreSig := c.preSignatures[lindell17.Party1]
					p2PreSig := c.preSignatures[lindell17.Party2]

					signature := ecdsa.Adapt(secp256k1, wit, p2PreSig)                // Party 2
					witness, _ := ecdsa.Extract(secp256k1, stmt, p1PreSig, signature) // Party 1

					if witness.Equal(wit) != true {
						t.Fatal("Witnesses are not equal")
					}

					pk := (*keys.PublicKey)(qShared)
					isValid, _ := ecdsa.Verify(secp256k1, pk, hash, signature)

					if isValid != true {
						t.Fatal("Signature verification failed")
					}

					recPk, _ := ecdsa.RecoverPublicKey(secp256k1, hash, signature)

					if recPk.Equal(pk) != true {
						t.Fatal("Public key recovery failed")
					}

					break coord
				}
			}
		}
	})

	t.Run("Sign / Verify (invalid)", func(t *testing.T) {
		t.Parallel()

		errCh := make(chan error, 2)
		outCh := make(chan lindell17.Message, 2)
		resCh := make(chan lindell17.Result, 2)

		message1 := []byte("Hello World")
		message2 := []byte("Hello, World")
		checksum1 := sha256.Sum256(message1)
		checksum2 := sha256.Sum256(message2)
		hash1 := checksum1[:]
		hash2 := checksum2[:]

		p1 := party1.NewParty1(p1Params, hash1, stmt, pStmt, outCh, resCh)
		p2 := party2.NewParty2(p2Params, hash1, stmt, pStmt, outCh, resCh)

		if _, err := p1.Start(); err != nil {
			errCh <- err
		}

		if _, err := p2.Start(); err != nil {
			errCh <- err
		}

		var counter int32
		c := newContainer()

	coord:
		for {
			select {
			case msg := <-outCh:
				switch msg.To() {
				case lindell17.Party1:
					if _, err := p1.Process(msg); err != nil {
						errCh <- err
					}
				case lindell17.Party2:
					if _, err := p2.Process(msg); err != nil {
						errCh <- err
					}
				}
			case err := <-errCh:
				t.Fatalf("expected no error, got %v", err)
			case result := <-resCh:
				atomic.AddInt32(&counter, 1)

				switch result.From() {
				case lindell17.Party1:
					res := result.(*party1.Result)
					c.add(result.From(), res.PreSignature)
				case lindell17.Party2:
					res := result.(*party2.Result)
					c.add(result.From(), res.PreSignature)
				}

				if atomic.LoadInt32(&counter) == 2 {
					p1PreSig := c.preSignatures[lindell17.Party1]
					p2PreSig := c.preSignatures[lindell17.Party2]

					signature := ecdsa.Adapt(secp256k1, wit, p2PreSig)                // Party 2
					witness, _ := ecdsa.Extract(secp256k1, stmt, p1PreSig, signature) // Party 1

					if witness.Equal(wit) != true {
						t.Fatal("Witnesses are not equal")
					}

					pk := (*keys.PublicKey)(qShared)
					isValid, _ := ecdsa.Verify(secp256k1, pk, hash2, signature)

					if isValid != false {
						t.Fatal("Signature verification failed")
					}

					break coord
				}
			}
		}
	})

	t.Run("Sign - Invalid (s value > n / 2)", func(t *testing.T) {
		t.Parallel()

		errCh := make(chan error, 2)
		outCh := make(chan lindell17.Message, 2)
		resCh := make(chan lindell17.Result, 2)

		message := []byte("Hello World")
		checksum := sha256.Sum256(message)
		hash := checksum[:]

		p1 := party1.NewParty1(p1Params, hash, stmt, pStmt, outCh, resCh)
		p2 := party2.NewParty2(p2Params, hash, stmt, pStmt, outCh, resCh)

		if _, err := p1.Start(); err != nil {
			errCh <- err
		}

		if _, err := p2.Start(); err != nil {
			errCh <- err
		}

		var counter int32
		c := newContainer()

	coord:
		for {
			select {
			case msg := <-outCh:
				switch msg.To() {
				case lindell17.Party1:
					if _, err := p1.Process(msg); err != nil {
						errCh <- err
					}
				case lindell17.Party2:
					if _, err := p2.Process(msg); err != nil {
						errCh <- err
					}
				}
			case err := <-errCh:
				t.Fatalf("expected no error, got %v", err)
			case result := <-resCh:
				atomic.AddInt32(&counter, 1)

				switch result.From() {
				case lindell17.Party1:
					res := result.(*party1.Result)
					c.add(result.From(), res.PreSignature)
				case lindell17.Party2:
					res := result.(*party2.Result)
					c.add(result.From(), res.PreSignature)
				}

				if atomic.LoadInt32(&counter) == 2 {
					p2PreSig := c.preSignatures[lindell17.Party2]

					signature := ecdsa.Adapt(secp256k1, wit, p2PreSig) // Party 2

					nHalf := new(big.Int).Div(secp256k1.N(), big.NewInt(2))
					if signature.S.Cmp(nHalf) > 0 {
						t.Fatal("Signature's s value is > n / 2")
					}

					break coord
				}
			}
		}
	})

	t.Run("Party1 - Start - Invalid (Hash length)", func(t *testing.T) {
		t.Parallel()

		outCh := make(chan lindell17.Message, 1)
		resCh := make(chan lindell17.Result, 1)

		message := []byte("Hello World")
		checksum := sha256.Sum256(message)
		hash := checksum[:]

		// Add one additional byte.
		hash = append(hash, 0x1)

		p1 := party1.NewParty1(p1Params, hash, stmt, pStmt, outCh, resCh)

		_, err := p1.Start()

		if !errors.Is(err, party1.ErrInvalidHashLength) {
			t.Errorf("want error %v, got %v", party1.ErrInvalidHashLength, err)
		}
	})

	t.Run("Party2 - Start - Invalid (Hash length)", func(t *testing.T) {
		t.Parallel()

		outCh := make(chan lindell17.Message, 1)
		resCh := make(chan lindell17.Result, 1)

		message := []byte("Hello World")
		checksum := sha256.Sum256(message)
		hash := checksum[:]

		// Add one additional byte.
		hash = append(hash, 0x1)

		p2 := party2.NewParty2(p2Params, hash, stmt, pStmt, outCh, resCh)

		_, err := p2.Start()

		if !errors.Is(err, party2.ErrInvalidHashLength) {
			t.Errorf("want error %v, got %v", party2.ErrInvalidHashLength, err)
		}
	})

	t.Run("Party1 - Start - Invalid (Statement DLK proof)", func(t *testing.T) {
		t.Parallel()

		outCh := make(chan lindell17.Message, 1)
		resCh := make(chan lindell17.Result, 1)

		message := []byte("Hello World")
		checksum := sha256.Sum256(message)
		hash := checksum[:]

		// Generate a valid statement, but a DLK proof for a different point.
		_, stmt, _ := adaptor.GenerateHardRelation(secp256k1)
		scalar, _ := secp256k1.GetRandomScalar()
		point, _ := secp256k1.ScalarMultiply(scalar, secp256k1.G())
		pStmt, _ := proofs.GenerateDLKProof(secp256k1, point, scalar)

		p1 := party1.NewParty1(p1Params, hash, stmt, pStmt, outCh, resCh)

		_, err := p1.Start()

		if !errors.Is(err, party1.ErrInvalidStatementDLKProof) {
			t.Errorf("want error %v, got %v", party1.ErrInvalidStatementDLKProof, err)
		}
	})

	t.Run("Party2 - Start - Invalid (Statement DLK proof)", func(t *testing.T) {
		t.Parallel()

		outCh := make(chan lindell17.Message, 1)
		resCh := make(chan lindell17.Result, 1)

		message := []byte("Hello World")
		checksum := sha256.Sum256(message)
		hash := checksum[:]

		// Generate a valid statement, but a DLK proof for a different point.
		_, stmt, _ := adaptor.GenerateHardRelation(secp256k1)
		scalar, _ := secp256k1.GetRandomScalar()
		point, _ := secp256k1.ScalarMultiply(scalar, secp256k1.G())
		pStmt, _ := proofs.GenerateDLKProof(secp256k1, point, scalar)

		p2 := party2.NewParty2(p2Params, hash, stmt, pStmt, outCh, resCh)

		_, err := p2.Start()

		if !errors.Is(err, party2.ErrInvalidStatementDLKProof) {
			t.Errorf("want error %v, got %v", party2.ErrInvalidStatementDLKProof, err)
		}
	})
}

type container struct {
	mu            sync.Mutex
	preSignatures map[lindell17.Entity]*ecdsa.PreSignature
}

func newContainer() *container {
	return &container{
		preSignatures: make(map[lindell17.Entity]*ecdsa.PreSignature),
	}
}

func (c *container) add(entity lindell17.Entity, preSignature *ecdsa.PreSignature) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.preSignatures[entity] = preSignature
}
