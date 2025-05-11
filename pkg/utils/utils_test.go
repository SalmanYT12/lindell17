package utils_test

import (
	"math/big"
	"testing"

	"github.com/primefactor-io/lindell17/pkg/utils"
)

func TestUtils(t *testing.T) {
	t.Parallel()

	t.Run("GenerateSessionId", func(t *testing.T) {
		t.Parallel()

		bits := 128
		sid, _ := utils.GenerateSessionId(bits)

		// The sid will be a SHA-256 hash which has length 256 / 4 = 64.
		if len(sid) != 256/4 {
			t.Error("Session Id generation failed")
		}
	})

	t.Run("GenerateRandomBytes", func(t *testing.T) {
		t.Parallel()

		bits := 128
		bytes, _ := utils.GenerateRandomBytes(bits)

		if len(bytes)*8 != bits {
			t.Error("Random byte generation failed")
		}
	})

	t.Run("ExtendedEuclidean", func(t *testing.T) {
		t.Parallel()

		a := big.NewInt(1432)
		b := big.NewInt(123211)

		gcd, x, y := utils.ExtendedEuclidean(a, b)

		if gcd.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("want gcd to be 1, got %v", gcd)
		}

		if x.Cmp(big.NewInt(-22973)) != 0 {
			t.Errorf("want x to be -22973, got %v", x)
		}

		if y.Cmp(big.NewInt(267)) != 0 {
			t.Errorf("want y to be 267, got %v", y)
		}
	})

}
