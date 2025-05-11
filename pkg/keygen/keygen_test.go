package keygen_test

import (
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/primefactor-io/ecc/pkg/curves"
	"github.com/primefactor-io/lindell17/pkg/keygen/messages"
	"github.com/primefactor-io/lindell17/pkg/keygen/party1"
	"github.com/primefactor-io/lindell17/pkg/keygen/party2"
	"github.com/primefactor-io/lindell17/pkg/lindell17"
	"github.com/primefactor-io/paillier/pkg/cipher"
	"github.com/primefactor-io/paillier/pkg/keys"
)

const paillierBits = 1024

var p1Params *party1.Params
var p2Params *party2.Params

var secp256k1 = curves.Secp256k1

func TestMain(m *testing.M) {
	rangeProofBits := 40
	nthRootProofBits := 128

	p1Params = party1.NewParams(secp256k1, rangeProofBits, nthRootProofBits, paillierBits)
	p2Params = party2.NewParams(secp256k1, rangeProofBits, nthRootProofBits)

	m.Run()
}

func TestKeygen(t *testing.T) {
	t.Parallel()

	t.Run("Key Generation (valid)", func(t *testing.T) {
		t.Parallel()

		errCh := make(chan error, 2)
		outCh := make(chan lindell17.Message, 2)
		resCh := make(chan lindell17.Result, 2)

		p1 := party1.NewParty1(p1Params, outCh, resCh)
		p2 := party2.NewParty2(p2Params, outCh, resCh)

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
					c.addParty1KeyMaterial(res.KeyMaterial)
				case lindell17.Party2:
					res := result.(*party2.Result)
					c.addParty2KeyMaterial(res.KeyMaterial)
				}

				if atomic.LoadInt32(&counter) == 2 {
					keys1 := c.p1KeyMaterial
					keys2 := c.p2KeyMaterial

					x1Dec, _ := cipher.Decrypt(keys1.Sk, keys2.X1Enc)
					x1Rec := new(big.Int).SetBytes(x1Dec)

					if keys1.X1.Cmp(x1Rec) != 0 {
						t.Fatal("Key generation failed (x1 verification)")
					}
					if keys1.Pk.Equal(keys2.Pk) != true {
						t.Fatal("Key generation failed (pk verification)")
					}
					if keys1.Q.Equal(keys2.Q) != true {
						t.Fatal("Key generation failed (q verification)")
					}

					break coord
				}
			}
		}
	})

	t.Run("Key Generation - Invalid (Q1)", func(t *testing.T) {
		t.Parallel()

		errCh := make(chan error, 2)
		outCh := make(chan lindell17.Message, 2)
		resCh := make(chan lindell17.Result, 2)

		p1 := party1.NewParty1(p1Params, outCh, resCh)
		p2 := party2.NewParty2(p2Params, outCh, resCh)

		if _, err := p1.Start(); err != nil {
			errCh <- err
		}

		if _, err := p2.Start(); err != nil {
			errCh <- err
		}

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
					if msg.MessageId() == 3 {
						// Parse old message.
						msg := msg.(*messages.Message3)

						sid := msg.SessionId()
						pk := msg.Pk
						pNthRoot := msg.PNthRoot
						x1Enc := msg.X1Enc
						pRange := msg.PRange

						// Compute new, random Q1.
						x1, _ := secp256k1.GetRandomScalar()
						q1, _ := secp256k1.ScalarMultiply(x1, secp256k1.G())

						// Replace existing message.
						msg = messages.NewMessage3(sid, q1, pk, pNthRoot, x1Enc, pRange)

						// Inject faulty message.
						if _, err := p2.Process(msg); err != nil {
							errCh <- err
						}

						break
					}

					if _, err := p2.Process(msg); err != nil {
						errCh <- err
					}
				}
			case err := <-errCh:
				if !errors.Is(err, party2.ErrInvalidQ1Commitment) {
					t.Fatalf("want error %v, got %v", party2.ErrInvalidQ1Commitment, err)
				}

				break coord
			}
		}
	})

	t.Run("Key Generation - Invalid (Q2)", func(t *testing.T) {
		t.Parallel()

		errCh := make(chan error, 2)
		outCh := make(chan lindell17.Message, 2)
		resCh := make(chan lindell17.Result, 2)

		p1 := party1.NewParty1(p1Params, outCh, resCh)
		p2 := party2.NewParty2(p2Params, outCh, resCh)

		if _, err := p1.Start(); err != nil {
			errCh <- err
		}

		if _, err := p2.Start(); err != nil {
			errCh <- err
		}

	coord:
		for {
			select {
			case msg := <-outCh:
				switch msg.To() {
				case lindell17.Party1:
					if msg.MessageId() == 2 {
						// Parse old message.
						msg := msg.(*messages.Message2)

						sid := msg.SessionId()
						pQ2 := msg.PQ2

						// Compute new, random Q2.
						x2, _ := secp256k1.GetRandomScalar()
						q2, _ := secp256k1.ScalarMultiply(x2, secp256k1.G())

						// Replace existing message.
						msg = messages.NewMessage2(sid, q2, pQ2)

						// Inject faulty message.
						if _, err := p1.Process(msg); err != nil {
							errCh <- err
						}

						break
					}
					if _, err := p1.Process(msg); err != nil {
						errCh <- err
					}
				case lindell17.Party2:
					if _, err := p2.Process(msg); err != nil {
						errCh <- err
					}
				}
			case err := <-errCh:
				if !errors.Is(err, party1.ErrInvalidQ2DLKProof) {
					t.Fatalf("want error %v, got %v", party1.ErrInvalidQ2DLKProof, err)
				}

				break coord
			}
		}
	})

	t.Run("Key Generation - Invalid (Paillier pk)", func(t *testing.T) {
		t.Parallel()

		errCh := make(chan error, 2)
		outCh := make(chan lindell17.Message, 2)
		resCh := make(chan lindell17.Result, 2)

		p1 := party1.NewParty1(p1Params, outCh, resCh)
		p2 := party2.NewParty2(p2Params, outCh, resCh)

		if _, err := p1.Start(); err != nil {
			errCh <- err
		}

		if _, err := p2.Start(); err != nil {
			errCh <- err
		}

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
					if msg.MessageId() == 3 {
						// Parse old message.
						msg := msg.(*messages.Message3)

						sid := msg.SessionId()
						q1 := msg.Q1
						pNthRoot := msg.PNthRoot
						x1Enc := msg.X1Enc
						pRange := msg.PRange

						// Compute new Pailllier pk.
						_, pk, _ := keys.GenerateKeys(paillierBits)

						// Replace existing message.
						msg = messages.NewMessage3(sid, q1, pk, pNthRoot, x1Enc, pRange)

						// Inject faulty message.
						if _, err := p2.Process(msg); err != nil {
							errCh <- err
						}

						break
					}

					if _, err := p2.Process(msg); err != nil {
						errCh <- err
					}
				}
			case err := <-errCh:
				if !errors.Is(err, party2.ErrInvalidNthRootProof) {
					t.Fatalf("want error %v, got %v", party2.ErrInvalidNthRootProof, err)
				}

				break coord
			}
		}
	})

	t.Run("Key Generation - Invalid (x1)", func(t *testing.T) {
		t.Parallel()

		errCh := make(chan error, 2)
		outCh := make(chan lindell17.Message, 2)
		resCh := make(chan lindell17.Result, 2)

		p1 := party1.NewParty1(p1Params, outCh, resCh)
		p2 := party2.NewParty2(p2Params, outCh, resCh)

		if _, err := p1.Start(); err != nil {
			errCh <- err
		}

		if _, err := p2.Start(); err != nil {
			errCh <- err
		}

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
					if msg.MessageId() == 3 {
						// Parse old message.
						msg := msg.(*messages.Message3)

						sid := msg.SessionId()
						q1 := msg.Q1
						pk := msg.Pk
						pNthRoot := msg.PNthRoot
						pRange := msg.PRange

						// Compute new, random x1 and its encryption.
						x1, _ := secp256k1.GetRandomScalar()
						x1Enc, _ := cipher.Encrypt(pk, x1.Bytes())

						// Replace existing message.
						msg = messages.NewMessage3(sid, q1, pk, pNthRoot, x1Enc, pRange)

						// Inject faulty message.
						if _, err := p2.Process(msg); err != nil {
							errCh <- err
						}

						break
					}

					if _, err := p2.Process(msg); err != nil {
						errCh <- err
					}
				}
			case err := <-errCh:
				if !errors.Is(err, party2.ErrInvalidRangeProof) {
					t.Fatalf("want error %v, got %v", party2.ErrInvalidRangeProof, err)
				}

				break coord
			}
		}
	})
}

type container struct {
	mu            sync.Mutex
	p1KeyMaterial *party1.KeyMaterial
	p2KeyMaterial *party2.KeyMaterial
}

func (c *container) addParty1KeyMaterial(keyMaterial *party1.KeyMaterial) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.p1KeyMaterial = keyMaterial
}

func (c *container) addParty2KeyMaterial(keyMaterial *party2.KeyMaterial) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.p2KeyMaterial = keyMaterial
}
