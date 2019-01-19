package noise

import (
	"encoding/hex"
	"fmt"
	"github.com/flynn/noise"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func TestPerformXXHandshake(t *testing.T) {

	// Handshake result.
	type hsResult struct {
		conn net.Conn
		enc  *noise.CipherState
		dec  *noise.CipherState
		err  error
	}

	// Generate keys for A & B entities.
	var aSK, bSK [kLen]byte
	aSK[0], bSK[0] = 1, 2
	aPK, bPK := PubKeyFromSecKey(aSK), PubKeyFromSecKey(bSK)

	// Create initial handshake states for A & B.
	hsA, err := NewXXHandshakeState(true, aPK, aSK)
	require.NoError(t, err)
	hsB, err := NewXXHandshakeState(false, bPK, bSK)
	require.NoError(t, err)

	// Create connection pipe between A & B.
	connA, connB := net.Pipe()

	// Perform handshake for A.
	chanA := make(chan hsResult, 1)
	go func() {
		enc, dec, err := PerformXXHandshake(connA, true, hsA)
		chanA <- hsResult{connA, enc, dec, err}
	}()

	// Perform handshake for B.
	chanB := make(chan hsResult, 1)
	go func() {
		enc, dec, err := PerformXXHandshake(connB, false, hsB)
		chanB <- hsResult{connB, enc, dec, err}
	}()

	// Check handshake result for A.
	a := <-chanA
	require.NoError(t, a.err)
	require.NotNil(t, a.enc)
	require.NotNil(t, a.dec)

	// Check handshake result for B.
	b := <-chanB
	require.NoError(t, b.err)
	require.NotNil(t, b.enc)
	require.NotNil(t, b.dec)

	// Tests delivery between A & B.
	testSend := func(msg string, src, dst hsResult) {
		errChan, recChan := make(chan error, 2), make(chan []byte, 1)
		go func() {
			errChan <- WriteCiphertext(src.conn, src.enc, []byte(msg))
		}()
		go func() {
			rec, err := ReadCiphertext(dst.conn, dst.dec)
			errChan <- err
			recChan <- rec
		}()
		require.NoError(t, <-errChan)
		require.NoError(t, <-errChan)
		require.Equal(t, msg, string(<-recChan))
	}

	// Test encrypted delivery between A & B.
	for i := 0; i < 100; i++ {
		testSend(fmt.Sprintf("hello %d from %s", i, hex.EncodeToString(aPK[:])), a, b)
		testSend(fmt.Sprintf("hello %d from %s", i, hex.EncodeToString(bPK[:])), b, a)
	}
}