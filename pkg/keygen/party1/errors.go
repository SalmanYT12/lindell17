package party1

import "fmt"

var (
	// ErrSampleScalarX1 is returned if the random scalar x1 can't be sampled.
	ErrSampleScalarX1 = fmt.Errorf("unable to sample random scalar x1")
	// ErrComputeQ1 is returned if Q1 can't be computed.
	ErrComputeQ1 = fmt.Errorf("unable to compute Q1")
	// ErrCommitToQ1 is returned if the commitment to Q1 can't be computed.
	ErrCommitToQ1 = fmt.Errorf("unable to commit to Q1")
	// ErrGenerateQ1DLKProof is returned if the Q1 DLK proof can't be generated.
	ErrGenerateQ1DLKProof = fmt.Errorf("unable to generate Q1 DLK proof")
	// ErrInvalidQ2DLKProof is returned if the Q2 DLK proof is invalid.
	ErrInvalidQ2DLKProof = fmt.Errorf("invalid Q2 DLK proof")
	// ErrGeneratePaillierKeys is returned if the Paillier keys can't be generated.
	ErrGeneratePaillierKeys = fmt.Errorf("unable to generate Paillier keys")
	// ErrGenerateNthRootProof is returned if the Nth root proof can't be generated.
	ErrGenerateNthRootProof = fmt.Errorf("unable to generate Nth root proof")
	// ErrEncryptX1 is returned if x1 can't be encrypted.
	ErrEncryptX1 = fmt.Errorf("unable to encrypt x1")
	// ErrGenerateRangeProof is returned if the range proof can't be generated.
	ErrGenerateRangeProof = fmt.Errorf("unable to generate range proof")
	// ErrInitializeDLEncProofProver is returned if the DLEnc proof prover can't be initialized.
	ErrInitializeDLEncProofProver = fmt.Errorf("unable to initialize DLEnc proof prover")
	// ErrProcessDLEncProofMessage1 is returned if the DLEnc proof message 1 can't be processed.
	ErrProcessDLEncProofMessage1 = fmt.Errorf("unable to process DLEnc proof message 1")
	// ErrProcessDLEncProofMessage3 is returned if the DLEnc proof message 3 can't be processed.
	ErrProcessDLEncProofMessage3 = fmt.Errorf("unable to process DLEnc proof message 3")
	// ErrInvalidDLEncProof is returned if the DLEnc proof is invalid.
	ErrInvalidDLEncProof = fmt.Errorf("invalid DLEnc proof")
	// ErrComputeQ is returned if Q can't be computed.
	ErrComputeQ = fmt.Errorf("unable to compute Q")
)
