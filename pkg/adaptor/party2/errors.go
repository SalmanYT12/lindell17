package party2

import "fmt"

var (
	// ErrInvalidHashLength is returned if the hash length is invalid.
	ErrInvalidHashLength = fmt.Errorf("invalid hash length")
	// ErrInvalidStatementDLKProof is returned if the statement DLK proof is invalid.
	ErrInvalidStatementDLKProof = fmt.Errorf("invalid statement DLK proof")
	// ErrSampleNonceK2 is returned if the random nonce k2 can't be sampled.
	ErrSampleNonceK2 = fmt.Errorf("unable to sample random nonce k2")
	// ErrComputeR2 is returned if R2 can't be computed.
	ErrComputeR2 = fmt.Errorf("unable to compute R2")
	// ErrCommitToR2 is returned if the commitment to R2 can't be computed.
	ErrCommitToR2 = fmt.Errorf("unable to commit to R2")
	// ErrGenerateR2DLKProof is returned if the R2 DLK proof can't be generated.
	ErrGenerateR2DLKProof = fmt.Errorf("Unable to generate R2 DLK proof")
	// ErrComputeR2Prime is returned if R2' can't be computed.
	ErrComputeR2Prime = fmt.Errorf("unable to compute R2'")
	// ErrCommitToR2Prime is returned if the commitment to R2' can't be computed.
	ErrCommitToR2Prime = fmt.Errorf("unable to commit to R2'")
	// ErrGenerateDLEqProof is returned if the DLEq proof can't be generated.
	ErrGenerateDLEqProof = fmt.Errorf("unable to generate DLEq proof")
	// ErrInvalidR1DLKProof is returned if the R1 DLK proof is invalid.
	ErrInvalidR1DLKProof = fmt.Errorf("invalid R1 DLK proof")
	// ErrInvalidDLEqProof is returned if the DLEq proof is invalid.
	ErrInvalidDLEqProof = fmt.Errorf("invalid DLEq proof")
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
	// ErrComputeK2TimesR1 is returned if k2 * R1 can't be computed.
	ErrComputeK2TimesR1 = fmt.Errorf("unable to compute k2 * R1")
	// ErrComputeUTimesG is returned if u * G can't be computed.
	ErrComputeUTimesG = fmt.Errorf("unable to compute u * G")
	// ErrComputeVTimesQ is returned if v * Q can't be computed.
	ErrComputeVTimesQ = fmt.Errorf("unable to compute v * Q")
	// ErrComputeUTimesGPlusVTimesQ is returned if (u * G) + (v * Q) can't be computed.
	ErrComputeUTimesGPlusVTimesQ = fmt.Errorf("unable to compute (u * G) + (v * Q)")
	// ErrInvalidResult is returned if the result of (u * G) + (v * Q) isn't equal to k2 * R1.
	ErrInvalidResult = fmt.Errorf("invalid result (k2 * R1 != (u * G) + (v * Q))")
)
