package party2

import "fmt"

var (
	// ErrSampleScalarX2 is returned if the random scalar x2 can't be sampled.
	ErrSampleScalarX2 = fmt.Errorf("unable to sample random scalar x2")
	// ErrComputeQ2 is returned if Q2 can't be compted.
	ErrComputeQ2 = fmt.Errorf("unable to compute Q2")
	// ErrGenerateQ2DLKProof is returned if the Q2 DLK proof can't be generated.
	ErrGenerateQ2DLKProof = fmt.Errorf("unable to generate Q2 DLK proof")
	// ErrInvalidQ1Commitment is returned if the Q1 commitment is invalid.
	ErrInvalidQ1Commitment = fmt.Errorf("invalid Q1 commitment")
	// ErrInvalidQ1DLKProof is returned if the Q1 DLK proof is invalid.
	ErrInvalidQ1DLKProof = fmt.Errorf("invalid Q1 DLK proof")
	// ErrInvalidNthRootProof is returned if the Nth root proof is invalid.
	ErrInvalidNthRootProof = fmt.Errorf("invalid Nth root proof")
	// ErrInvalidRangeProof is returned if the range proof is invalid.
	ErrInvalidRangeProof = fmt.Errorf("invalid range proof")
	// ErrInitializeDLEncProofVerifier is returned if the DLEnc proof verifier can't be initialized.
	ErrInitializeDLEncProofVerifier = fmt.Errorf("unable to initialize DLEnc proof verifier")
	// ErrProcessDLEncProofMessage2 is returned if the DLEnc proof message 2 can't be processed.
	ErrProcessDLEncProofMessage2 = fmt.Errorf("unable to process DLEnc proof message 2")
	// ErrProcessDLEncProofMessage4 is returned if the DLEnc proof message 4 can't be processed.
	ErrProcessDLEncProofMessage4 = fmt.Errorf("unable to process DLEnc proof message 4")
	// ErrInvalidDLEncProof is returned if the DLEnc proof is invalid.
	ErrInvalidDLEncProof = fmt.Errorf("invalid DLEnc proof")
	// ErrComputeQ is returned if Q can't be computed.
	ErrComputeQ = fmt.Errorf("unable to compute Q")
)
