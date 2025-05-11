package verifier

import "fmt"

var (
	// ErrSampleA is returned if the random value a can't be sampled.
	ErrSampleA = fmt.Errorf("unable to sample random a")
	// ErrSampleB is returned if the random value b can't be sampled.
	ErrSampleB = fmt.Errorf("unable to sample random b")
	// ErrCommitToAAndB is returned if the commitment to a and b can't be computed.
	ErrCommitToAAndB = fmt.Errorf("unable to commit to a and b")
	// ErrEncryptB is returned if b can't be encrypted.
	ErrEncryptB = fmt.Errorf("unable to encrypt b")
	// ErrInvalidGCD is returned if the GCD is invalid.
	ErrInvalidGCD = fmt.Errorf("invalid gcd (gcd(r, N) != 1)")
	// ErrMultiplyPlaintextValue is returned if the plaintext multiplication can't be computed.
	ErrMultiplyPlaintextValue = fmt.Errorf("unable to multiply plaintext of x1Enc with a")
	// ErrComputeATimesQ1 is returned if a * Q1 can't be computed.
	ErrComputeATimesQ1 = fmt.Errorf("unable to compute a * Q1")
	// ErrComputeBTimesG is returned if b * G can't be computed.
	ErrComputeBTimesG = fmt.Errorf("unable to compute b * G")
	// ErrComputeATimesQ1PlusBTimesG is returned if (a * Q1) + (b * G) can't be computed.
	ErrComputeATimesQ1PlusBTimesG = fmt.Errorf("unable to compute (a * Q1) + (b * G)")
)
