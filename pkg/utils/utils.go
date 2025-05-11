package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/big"

	"github.com/primefactor-io/lindell17/pkg/lindell17"
)

// HashLength is the number of bytes a 256 bit hash has.
const HashLength = 32

// GenerateSessionId generates a session id that's used in protocol messages
// to group messages belonging to the same session.
func GenerateSessionId(bits int) (string, error) {
	bz, err := GenerateRandomBytes(bits)
	if err != nil {
		return "", lindell17.ErrGenerateSessionId
	}

	checksum := sha256.Sum256(bz)
	sessionId := hex.EncodeToString(checksum[:])

	return sessionId, nil
}

// GenerateRandomBytes generates a byte slice that contains the number of
// desired bits.
// Returns an error if the random bytes can't be generated.
func GenerateRandomBytes(bits int) ([]byte, error) {
	numBytes := (bits + 7) / 8
	randBytes := make([]byte, numBytes)

	// Sample a slice of random bytes.
	_, err := io.ReadFull(rand.Reader, randBytes)
	if err != nil {
		return nil, ErrGenerateRandomBytes
	}

	return randBytes, nil
}

// ExtendedEuclidean runs the extended Euclidean algorithm to obtain the values
// gcd, x and y.
func ExtendedEuclidean(a *big.Int, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	x := big.NewInt(0)
	y := big.NewInt(1)
	u := big.NewInt(1)
	v := big.NewInt(0)

	// Run loop while a != 0.
	for a.Cmp(big.NewInt(0)) != 0 {
		q := new(big.Int).Div(b, a) // b / a
		r := new(big.Int).Mod(b, a) // b % a

		uq := new(big.Int).Mul(u, q) // u * q
		vq := new(big.Int).Mul(v, q) // v * q

		m := new(big.Int).Sub(x, uq) // x - (u * q)
		n := new(big.Int).Sub(y, vq) // x - (v * q)

		b = a
		a = r
		x = u
		y = v
		u = m
		v = n
	}

	gcd := b

	return gcd, x, y
}
