package prover

import "fmt"

var (
	// ErrDecryptCiphertext is returned if the ciphertext can't be decrypted.
	ErrDecryptCiphertext = fmt.Errorf("unable to decrypt ciphertext")
	// ErrComputeQHat is returned if Q^ can't be computed.
	ErrComputeQHat = fmt.Errorf("unable to compute Q^")
	// ErrCommitToQHat is returned if the commitment to Q^ can't be computed.
	ErrCommitToQHat = fmt.Errorf("unable to commit to Q^")
)
