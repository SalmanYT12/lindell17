package party2

import "fmt"

var (
	// ErrInvalidHashLength is returned if the hash length is invalid.
	ErrInvalidHashLength = fmt.Errorf("invalid hash length")
	// ErrSampleNonceK2 is returned if the random nonce k2 can't be sampled.
	ErrSampleNonceK2 = fmt.Errorf("unable to sample random nonce k2")
	// ErrComputeR2 is returned if R2 can't be computed.
	ErrComputeR2 = fmt.Errorf("unable to compute R2")
	// ErrGenerateR2DLKProof is returned if the R2 DLK proof can't be generated.
	ErrGenerateR2DLKProof = fmt.Errorf("unable to generate R2 DLK proof")
	// ErrInvalidR1Commitment is returned if the R1 commitment is invalid.
	ErrInvalidR1Commitment = fmt.Errorf("invalid R1 commitment")
	// ErrInvalidR1DLKProof is returned if the R1 DLK proof is invalid.
	ErrInvalidR1DLKProof = fmt.Errorf("invalid R1 DLK proof")
	// ErrComputeR is returned if R can't be computed.
	ErrComputeR = fmt.Errorf("unable to compute R")
	// ErrSampleP is returned if p can't be sampled.
	ErrSampleP = fmt.Errorf("unable to sample random p")
	// ErrComputeC1 is returned if c1 can't be computed.
	ErrComputeC1 = fmt.Errorf("unable to compute c1")
	// ErrInvalidGCD is returned if the GCD is invalid.
	ErrInvalidGCD = fmt.Errorf("invalid gcd (gcd(nonce, N) != 1)")
	// ErrComputeC2 is returned if c2 can't be computed.
	ErrComputeC2 = fmt.Errorf("unable to compute c2")
)
