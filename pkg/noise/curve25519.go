package noise

import (
	"golang.org/x/crypto/curve25519"
	"io"
)

const (
	ks = 32
)

func RandSecKey(r io.Reader) [ks]byte {
	var sk [ks]byte
	if n, err := io.ReadFull(r, sk[:]); err != nil {
		panic(err)
	} else if n != ks {
		panic("invalid rand read length")
	}
	return sk
}

func PubKeyFromSecKey(sk [ks]byte) [ks]byte {
	var pk [ks]byte
	curve25519.ScalarBaseMult(&pk, &sk)
	return pk
}

func RandPair(r io.Reader) ([ks]byte, [ks]byte) {
	sk := RandSecKey(r)
	pk := PubKeyFromSecKey(sk)
	return pk, sk
}

func ECDH(localSK, remotePK [ks]byte) [ks]byte {
	var ecdh [ks]byte
	curve25519.ScalarMult(&ecdh, &localSK, &remotePK)
	return ecdh
}