package cryptopals

import (
	"log"
	"encoding/hex"
	"encoding/base64"
)

func hexToBase64(hs string) (string, error) {
	decoded, err := hex.DecodeString(hs)
	if err != nil {
		return "", err
	}
	log.Printf("%s\n", decoded)
	val := base64.StdEncoding.EncodeToString(decoded)
	return val, nil
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xor: mismatched lengths")
	}
	res := make([]byte, len(a))
	for i := range a {
		res[i] = a[i] ^ b[i]
	}
	return res
}