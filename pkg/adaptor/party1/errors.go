package party1

import "fmt"

var (
	// ErrInvalidHashLength is returned if the hash length is invalid.
	ErrInvalidHashLength = fmt.Errorf("invalid hash length")
	// ErrInvalidStatementDLKProof is returned if the statement DLK proof is invalid.
	ErrInvalidStatementDLKProof = fmt.Errorf("invalid statement DLK proof")
	// ErrSampleNonceK1 is returned if the random nonce k1 can't be sampled.
	ErrSampleNonceK1 = fmt.Errorf("unable to sample random nonce k1")
	// ErrComputeR1 is returned if R1 can't be computed.
	ErrComputeR1 = fmt.Errorf("unable to compute R1")
	// ErrGenerateR1DLKProof is returned if the R1 DLK proof can't be generated.
	ErrGenerateR1DLKProof = fmt.Errorf("unable to generate R1 DLK proof")
	// ErrComputeR1Prime is returned if R1' can't be computed.
	ErrComputeR1Prime = fmt.Errorf("unable to compute R1'")
	// ErrGenerateDLEqProof is returned if the DLEq proof can't be generated.
	ErrGenerateDLEqProof = fmt.Errorf("unable to generate DLEq proof")
	// ErrInvalidR2Commitment is returned if the R2 commitment is invalid.
	ErrInvalidR2Commitment = fmt.Errorf("invalid R2 commitment")
	// ErrInvalidR2DLKProof is returned if the R2 DLK proof is invalid.
	ErrInvalidR2DLKProof = fmt.Errorf("invalid R2 DLK proof")
	// ErrInvalidR2PrimeCommitment is returned if the R2' commitment is invalid.
	ErrInvalidR2PrimeCommitment = fmt.Errorf("invalid R2' commitment")
	// ErrInvalidDLEqProof is returned if the DLEq proof is invalid.
	ErrInvalidDLEqProof = fmt.Errorf("invalid DLEq proof")
	// ErrComputeR is returned if R can't be computed.
	ErrComputeR = fmt.Errorf("unable to compute R")
	// ErrDecryptCiphertext is returned if the ciphertext can't be decrypted.
	ErrDecryptCiphertext = fmt.Errorf("unable to decrypt ciphertext")
	// ErrComputeU1TimesG is returned if u_1 * G can't be computed.
	ErrComputeU1TimesG = fmt.Errorf("unable to compute u_1 * G")
	// ErrComputeU2TimesQ is returned if u_2 * Q can't be computed.
	ErrComputeU2TimesQ = fmt.Errorf("unable to compute u_2 * Q")
	// ErrComputeU1TimesGPlusU2TimesQ is returned if (u_1 * G) + (u_2 * Q) can't be computed.
	ErrComputeU1TimesGPlusU2TimesQ = fmt.Errorf("unable to compute (u_1 * G) + (u_2 * Q)")
	// ErrInvalidResult is returned if the result of (u_1 * G) + (u_2 * Q) isn't equal to R2.
	ErrInvalidResult = fmt.Errorf("invalid result (R2 != (u_1 * G) + (u_2 * Q))")
)
