package noise

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"

	"github.com/flynn/noise"
)

/*

# XX Handshake

-> e
<- e, ee, s, es
-> s, se

*/

type Packet []byte

func WritePlaintext(w io.Writer, data []byte) error {
	l := len(data)
	if l > 0xffff {
		return errors.New("data too large to contain within a packet")
	}
	if err := binary.Write(w, binary.BigEndian, uint16(l)); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func ReadPlaintext(r io.Reader) ([]byte, error) {
	var l uint16
	if err := binary.Read(r, binary.BigEndian, &l); err != nil {
		return nil, err
	}
	data := make([]byte, l)
	_, err := io.ReadFull(r, data)
	return data, err
}

func WriteCiphertext(w io.Writer, enc *noise.CipherState, plaintext []byte) error {
	ciphertext := enc.Encrypt(nil, nil, plaintext)
	return WritePlaintext(w, ciphertext)
}

func ReadCiphertext(r io.Reader, dec *noise.CipherState) ([]byte, error) {
	ciphertext, err := ReadPlaintext(r)
	if err != nil {
		return nil, err
	}
	return dec.Decrypt(nil, nil, ciphertext)
}

func NewXXHandshakeState(init bool, localPK, localSK [32]byte) (*noise.HandshakeState, error) {
	return noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA512),
		Random:      rand.Reader,
		Pattern:     noise.HandshakeXX,
		Initiator:   init,
		StaticKeypair: noise.DHKey{
			Public:  localPK[:],
			Private: localSK[:],
		},
	})
}

func PerformXXHandshake(rw io.ReadWriter, init bool, hs *noise.HandshakeState) (enc, dec *noise.CipherState, err error) {
	edgeType := func() string {
		if init {
			return "INIT"
		}
		return "RESP"
	}

	hsRead := func() error {
		var msg []byte
		defer func() {
			log.Printf("[%s:R] len(%d) msg(%s) err(%v)\n",
				edgeType(), len(msg), hex.EncodeToString(msg), err)
		}()

		if msg, err = ReadPlaintext(rw); err != nil {
			return err
		}
		_, enc, dec, err = hs.ReadMessage(nil, msg)
		return err
	}

	hsWrite := func() error {
		var msg []byte
		defer func() {
			log.Printf("[%s:W] len(%d) msg(%s) err(%v)\n",
				edgeType(), len(msg), hex.EncodeToString(msg), err)
		}()

		if msg, enc, dec, err = hs.WriteMessage(nil, nil); err != nil {
			return err
		}
		err = WritePlaintext(rw, msg)
		return err
	}

	if init {
		if hsWrite() != nil {
			log.Println("[INIT:W(1)] err:", err)
			return
		}
		if hsRead() != nil {
			log.Println("[INIT:R(2)] err:", err)
			return
		}
		if hsWrite() != nil {
			log.Println("[INIT:W(3)] err:", err)
			return
		}
	} else {
		if hsRead() != nil {
			log.Println("[RESP:R(1)] err:", err)
			return
		}
		if hsWrite() != nil {
			log.Println("[RESP:W(2)] err:", err)
			return
		}
		if hsRead() != nil {
			log.Println("[RESP:R(3)] err:", err)
			return
		}
		enc, dec = dec, enc
	}
	return
}
