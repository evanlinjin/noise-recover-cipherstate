package noise

import (
	"crypto/rand"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRandSecKey(t *testing.T) {
	t.Run("PanicWithNilReader", func(t *testing.T) {
		defer func() {
			require.NotNil(t, recover())
		}()
		sk := RandSecKey(nil)
		require.Equal(t, [kLen]byte{}, sk)
	})
}

func TestECDH(t *testing.T) {
	aPK, aSK := RandPair(rand.Reader)
	bPK, bSK := RandPair(rand.Reader)

	aECDH := ECDH(aSK, bPK)
	bECDH := ECDH(bSK, aPK)
	require.Equal(t, aECDH, bECDH)
}
