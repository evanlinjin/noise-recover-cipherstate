package noise

import (
	"golang.org/x/crypto/curve25519"
	"io"
)

const (
	kLen = 32
)

func RandSecKey(r io.Reader) [kLen]byte {
	var sk [kLen]byte
	if n, err := io.ReadFull(r, sk[:]); err != nil {
		panic(err)
	} else if n != kLen {
		panic("invalid rand read length")
	}
	return sk
}

func PubKeyFromSecKey(sk [kLen]byte) [kLen]byte {
	var pk [kLen]byte
	curve25519.ScalarBaseMult(&pk, &sk)
	return pk
}

func RandPair(r io.Reader) ([kLen]byte, [kLen]byte) {
	sk := RandSecKey(r)
	pk := PubKeyFromSecKey(sk)
	return pk, sk
}

func ECDH(localSK, remotePK [kLen]byte) [kLen]byte {
	var ecdh [kLen]byte
	curve25519.ScalarMult(&ecdh, &localSK, &remotePK)
	return ecdh
}