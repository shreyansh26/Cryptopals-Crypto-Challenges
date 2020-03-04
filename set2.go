package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
	mathrand "math/rand"
	"time"
)

func padPKCS7(in []byte, blockLength int) []byte {
	if blockLength >= 256 {
		panic("can't pad to size higher than 255")
	}
	rem := blockLength - (len(in) % blockLength)
	out := make([]byte, len(in)+rem)
	copy(out, in)

	for i := len(in); i < len(out); i++ {
		out[i] = byte(rem)
	}
	return out
}

func encryptCBC(src []byte, b cipher.Block, iv []byte) []byte {
	bs := b.BlockSize()
	if len(src)%bs != 0 {
		panic("wrong input length")
	}
	if len(iv) != bs {
		panic("wrong iv length")
	}
	out := make([]byte, len(src))
	prev := iv
	for i := 0; i < len(src); i += bs {
		copy(out[i:], xor(src[i:i+bs], prev))
		b.Encrypt(out[i:], out[i:])
		prev = out[i : i+bs]
	}
	return out
}

func decryptCBC(src []byte, b cipher.Block, iv []byte) []byte {
	bs := b.BlockSize()
	if len(src)%bs != 0 {
		panic("wrong input length")
	}
	if len(iv) != bs {
		panic("wrong iv length")
	}

	out := make([]byte, len(src))
	prev := iv
	buf := make([]byte, bs)
	for i := 0; i < len(src); i += bs {
		b.Decrypt(buf, src[i:])
		copy(out[i:], xor(buf, prev))
		prev = src[i : i+bs]
	}
	return out
}

func encryptECB(text []byte, b cipher.Block) []byte {
	if len(text)%b.BlockSize() != 0 {
		panic("encryptECB: length not a multiple of BlockSize")
	}
	out := make([]byte, len(text))
	for i := 0; i < len(text); i += b.BlockSize() {
		b.Encrypt(out[i:], text[i:])
	}
	return out
}

func newECBCBCOracle() func([]byte) []byte {
	key := make([]byte, 16)
	rand.Read(key)

	b, _ := aes.NewCipher(key)
	return func(in []byte) []byte {
		mathrand.Seed(time.Now().UTC().UnixNano())
		prefix := make([]byte, 5+mathrand.Intn(5))
		rand.Read(prefix)
		suffix := make([]byte, 5+mathrand.Intn(5))
		rand.Read(suffix)

		msg := append(append(prefix, in...), suffix...)
		msg = padPKCS7(msg, 16)

		if mathrand.Intn(10)%2 == 0 {
			iv := make([]byte, 16)
			rand.Read(iv)
			return encryptCBC(msg, b, iv)
		}
		return encryptECB(msg, b)
	}
}

func newECBSuffixOracle(secret []byte) func([]byte) []byte {
	key := make([]byte, 16)
	rand.Read(key)

	b, _ := aes.NewCipher(key)
	return func(in []byte) []byte {
		time.Sleep(200 * time.Microsecond)
		msg := append(in, secret...)
		return encryptECB(padPKCS7(msg, 16), b)
	}
}

func recoverECBSuffix(oracle func([]byte) []byte) []byte {
	var bs int

	for blockSize := 2; blockSize < 100; blockSize++ {
		msg := bytes.Repeat([]byte{42}, blockSize*2)
		// msg = append(msg, 6)
		if detectAESECB(oracle(msg)[:blockSize*2], blockSize) {
			bs = blockSize
			break
		}
	}
	if bs == 0 {
		panic("couldn't detect block size")
	}
	log.Printf("bs: %d", bs)

	buildDict := func(known []byte) map[string]byte {
		dict := make(map[string]byte)

		msg := bytes.Repeat([]byte{42}, bs)
		msg = append(msg, known...)
		msg = append(msg, '?')
		msg = msg[len(msg)-bs:]

		for b := 0; b < 256; b++ {
			msg[bs-1] = byte(b)
			res := string(oracle(msg)[:bs])
			dict[res] = byte(b)
		}
		return dict
	}

	dict := buildDict(nil)
	msg := bytes.Repeat([]byte{42}, bs-1)
	res := string(oracle(msg)[:bs])
	firstByte := dict[res]
	fmt.Printf("First byte: %c / %v\n", firstByte, firstByte)

	var plaintext []byte
	for i := 0; i < len(oracle([]byte{})); i++ {
		dict := buildDict(plaintext)
		msg := bytes.Repeat([]byte{42}, mod(bs-i-1, bs))
		skip := i / bs * bs
		res := string(oracle(msg)[skip : skip+bs])
		plaintext = append(plaintext, dict[res])

		fmt.Printf("%c", dict[res])
	}
	fmt.Printf("\n")

	return nil
}

func mod(a, b int) int {
	return (a%b + b) % b
}
