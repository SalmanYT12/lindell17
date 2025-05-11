package utils

import "fmt"

// ErrGenerateRandomBytes is returned if the random bytes can't be generated.
var ErrGenerateRandomBytes = fmt.Errorf("unable to generate random bytes")
