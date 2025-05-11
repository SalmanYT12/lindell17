package sign_test

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/primefactor-io/ecc/pkg/curves"
	"github.com/primefactor-io/ecc/pkg/ecdsa"
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/ecc/pkg/keys"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/lindell17/pkg/sign/party1"
	"github.com/primefactor-io/lindell17/pkg/sign/party2"
	"github.com/primefactor-io/paillier/pkg/cipher"
	pKeys "github.com/primefactor-io/paillier/pkg/keys"
)

var p1Params *party1.Params
var p2Params *party2.Params
var qShared *elliptic.Point

var secp256k1 = curves.Secp256k1

func TestMain(m *testing.M) {
	// x1 should be in the range x1 >= 0 and x1 < q / 3.
	q3 := new(big.Int).Div(secp256k1.N(), big.NewInt(3)) // q / 3

	sk, pk, _ := pKeys.GenerateKeys(1024)

	x1, _ := secp256k1.GetRandomScalar(q3)
	x1Enc, _ := cipher.Encrypt(pk, x1.Bytes())

	x2, _ := secp256k1.GetRandomScalar()
	q2, _ := secp256k1.ScalarMultiply(x2, secp256k1.G())

	// Note that x1 * Q2 = x2 * Q1.
	qShared, _ = secp256k1.ScalarMultiply(x1, q2)

	p1Params = party1.NewParams(secp256k1, sk, qShared)
	p2Params = party2.NewParams(secp256k1, pk, x1Enc, x2)

	m.Run()
}

func TestSignVerify(t *testing.T) {
	t.Parallel()

	t.Run("Sign / Verify / Public Key Recovery (valid)", func(t *testing.T) {
		t.Parallel()

		errCh := make(chan error, 2)
		outCh := make(chan lindell17.Message, 2)
		resCh := make(chan lindell17.Result, 2)

		message := []byte("Hello World")
		checksum := sha256.Sum256(message)
		hash := checksum[:]

		p1 := party1.NewParty1(p1Params, hash, outCh, resCh)
		p2 := party2.NewParty2(p2Params, hash, outCh, resCh)

		if _, err := p1.Start(); err != nil {
			errCh <- err
		}

		if _, err := p2.Start(); err != nil {
			errCh <- err
		}

		var counter int32
		c := new(container)

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
					c.addSignature(res.Signature)
				case lindell17.Party2:
					res := result.(*party2.Result)
					c.addParty2ResultData(res.R, res.Ciphertext)
				}

				if atomic.LoadInt32(&counter) == 2 {
					if c.r == nil {
						t.Fatal("Signature's r value missing")
					}

					if c.ciphertext == nil {
						t.Fatal("Ciphertext missing")
					}

					pk := (*keys.PublicKey)(qShared)
					isValid, _ := ecdsa.Verify(secp256k1, pk, hash, c.signature)

					if isValid != true {
						t.Fatal("Signature verification failed")
					}

					recPk, _ := ecdsa.RecoverPublicKey(secp256k1, hash, c.signature)

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

		p1 := party1.NewParty1(p1Params, hash1, outCh, resCh)
		p2 := party2.NewParty2(p2Params, hash1, outCh, resCh)

		if _, err := p1.Start(); err != nil {
			errCh <- err
		}

		if _, err := p2.Start(); err != nil {
			errCh <- err
		}

		var counter int32
		c := new(container)

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
					c.addSignature(res.Signature)
				case lindell17.Party2:
					res := result.(*party2.Result)
					c.addParty2ResultData(res.R, res.Ciphertext)
				}

				if atomic.LoadInt32(&counter) == 2 {
					if c.r == nil {
						t.Fatal("Signature's r value missing")
					}

					if c.ciphertext == nil {
						t.Fatal("Ciphertext missing")
					}

					pk := (*keys.PublicKey)(qShared)
					isValid, _ := ecdsa.Verify(secp256k1, pk, hash2, c.signature)

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

		p1 := party1.NewParty1(p1Params, hash, outCh, resCh)
		p2 := party2.NewParty2(p2Params, hash, outCh, resCh)

		if _, err := p1.Start(); err != nil {
			errCh <- err
		}

		if _, err := p2.Start(); err != nil {
			errCh <- err
		}

		var counter int32
		c := new(container)

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
					c.addSignature(res.Signature)
				case lindell17.Party2:
					res := result.(*party2.Result)
					c.addParty2ResultData(res.R, res.Ciphertext)
				}

				if atomic.LoadInt32(&counter) == 2 {
					if c.r == nil {
						t.Fatal("Signature's r value missing")
					}

					if c.ciphertext == nil {
						t.Fatal("Ciphertext missing")
					}

					nHalf := new(big.Int).Div(secp256k1.N(), big.NewInt(2))
					if c.signature.S.Cmp(nHalf) > 0 {
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

		p1 := party1.NewParty1(p1Params, hash, outCh, resCh)

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

		p2 := party2.NewParty2(p2Params, hash, outCh, resCh)

		_, err := p2.Start()

		if !errors.Is(err, party2.ErrInvalidHashLength) {
			t.Errorf("want error %v, got %v", party2.ErrInvalidHashLength, err)
		}
	})
}

type container struct {
	mu         sync.Mutex
	signature  *ecdsa.Signature
	r          *big.Int
	ciphertext cipher.Ciphertext
}

func (c *container) addSignature(signature *ecdsa.Signature) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.signature = signature
}

func (c *container) addParty2ResultData(r *big.Int, ciphertext cipher.Ciphertext) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.r = r
	c.ciphertext = ciphertext
}
