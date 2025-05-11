package dlencproof_test

import (
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/primefactor-io/ecc/pkg/curves"
	"github.com/primefactor-io/ecc/pkg/elliptic"
	"github.com/primefactor-io/lindell17/pkg/dlenc_proof/prover"
	"github.com/primefactor-io/lindell17/pkg/dlenc_proof/verifier"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/paillier/pkg/cipher"
	"github.com/primefactor-io/paillier/pkg/keys"
)

var x1 *big.Int
var q1 *elliptic.Point
var sk *keys.PrivateKey
var pk *keys.PublicKey

var secp256k1 = curves.Secp256k1

func TestMain(m *testing.M) {
	x1, _ = secp256k1.GetRandomScalar()
	q1, _ = secp256k1.ScalarMultiply(x1, secp256k1.G())

	sk, pk, _ = keys.GenerateKeys(1024)

	m.Run()
}

func TestDLEncProof(t *testing.T) {
	t.Parallel()

	t.Run("Prove / Verify (valid)", func(t *testing.T) {
		t.Parallel()

		x1Enc, _ := cipher.Encrypt(pk, x1.Bytes())

		errCh := make(chan error, 2)
		outCh := make(chan lindell17.Message, 2)
		resCh := make(chan lindell17.Result, 2)

		pParams := prover.NewParams(secp256k1, sk, x1)
		vParams := verifier.NewParams(secp256k1, q1, pk, x1Enc)

		prov := prover.NewProver(pParams, outCh, resCh)
		verif := verifier.NewVerifier(vParams, outCh, resCh)

		if _, err := prov.Start(); err != nil {
			errCh <- err
		}

		if _, err := verif.Start(); err != nil {
			errCh <- err
		}

		var counter int32
		c := newContainer()

	coord:
		for {
			select {
			case msg := <-outCh:
				switch msg.To() {
				case lindell17.Prover:
					if _, err := prov.Process(msg); err != nil {
						errCh <- err
					}
				case lindell17.Verifier:
					if _, err := verif.Process(msg); err != nil {
						errCh <- err
					}
				}
			case err := <-errCh:
				t.Fatalf("expected no error, got %v", err)
			case result := <-resCh:
				atomic.AddInt32(&counter, 1)

				switch result.From() {
				case lindell17.Prover:
					res := result.(*prover.Result)
					c.add(result.From(), res.IsValid)
				case lindell17.Verifier:
					res := result.(*verifier.Result)
					c.add(result.From(), res.IsValid)
				}

				if atomic.LoadInt32(&counter) == 2 {
					proverRes := c.results[lindell17.Prover]
					verifierRes := c.results[lindell17.Verifier]

					if (proverRes == true && verifierRes == true) != true {
						t.Fatal("DLEnc proof verification failed")
					}

					break coord
				}
			}
		}
	})

	t.Run("Prove / Verify (invalid)", func(t *testing.T) {
		t.Parallel()

		x2, _ := secp256k1.GetRandomScalar()
		x2Enc, _ := cipher.Encrypt(pk, x2.Bytes())

		errCh := make(chan error, 2)
		outCh := make(chan lindell17.Message, 2)
		resCh := make(chan lindell17.Result, 2)

		pParams := prover.NewParams(secp256k1, sk, x1)
		vParams := verifier.NewParams(secp256k1, q1, pk, x2Enc)

		prov := prover.NewProver(pParams, outCh, resCh)
		verif := verifier.NewVerifier(vParams, outCh, resCh)

		if _, err := prov.Start(); err != nil {
			errCh <- err
		}

		if _, err := verif.Start(); err != nil {
			errCh <- err
		}

		var counter int32
		c := newContainer()

	coord:
		for {
			select {
			case msg := <-outCh:
				switch msg.To() {
				case lindell17.Prover:
					if _, err := prov.Process(msg); err != nil {
						errCh <- err
					}
				case lindell17.Verifier:
					if _, err := verif.Process(msg); err != nil {
						errCh <- err
					}
				}
			case err := <-errCh:
				t.Fatalf("expected no error, got %v", err)
			case result := <-resCh:
				atomic.AddInt32(&counter, 1)

				switch result.From() {
				case lindell17.Prover:
					res := result.(*prover.Result)
					c.add(result.From(), res.IsValid)
				case lindell17.Verifier:
					res := result.(*verifier.Result)
					c.add(result.From(), res.IsValid)
				}

				if atomic.LoadInt32(&counter) == 2 {
					proverRes := c.results[lindell17.Prover]
					verifierRes := c.results[lindell17.Verifier]

					if (proverRes == false && verifierRes == false) != true {
						t.Fatal("DLEnc proof verification failed")
					}

					break coord
				}
			}
		}
	})
}

type container struct {
	mu      sync.Mutex
	results map[lindell17.Entity]bool
}

func newContainer() *container {
	return &container{
		results: make(map[lindell17.Entity]bool),
	}
}

func (c *container) add(entity lindell17.Entity, result bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.results[entity] = result
}
