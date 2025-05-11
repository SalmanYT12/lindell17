package party1

import "fmt"

var (
	// ErrInvalidHashLength is returned if the hash length is invalid.
	ErrInvalidHashLength = fmt.Errorf("invalid hash length")
	// ErrSampleNonceK1 is returned if the random nonce k1 can't be sampled.
	ErrSampleNonceK1 = fmt.Errorf("unable to sample random nonce k1")
	// ErrComputeR1 is returned if R1 can't be computed.
	ErrComputeR1 = fmt.Errorf("unable to compute R1")
	// ErrCommitToR1 is returned if the commitment to R1 can't be computed.
	ErrCommitToR1 = fmt.Errorf("unable to commit to R1")
	// ErrGenerateR1DLKProof is returned if the R1 DLK proof can't be generated.
	ErrGenerateR1DLKProof = fmt.Errorf("unable to generate R1 DLK proof")
	// ErrInvalidR2DLKProof is returned if the R2 DLK proof is invalid.
	ErrInvalidR2DLKProof = fmt.Errorf("invalid R2 DLK proof")
	// ErrComputeR is returned if R can't be computed.
	ErrComputeR = fmt.Errorf("unable to compute R")
	// ErrInvalidR is returned if the recomputed r value doesn't match the partial signature's r value.
	ErrInvalidR = fmt.Errorf("recomputed r doesn't equal r of partial signature")
	// ErrDecryptCiphertext is returned if the ciphertext can't be decrypted.
	ErrDecryptCiphertext = fmt.Errorf("unable to decrypt ciphertext")
	// ErrInvalidSignature is returned if the signature is invalid.
	ErrInvalidSignature = fmt.Errorf("invalid signature")
)
