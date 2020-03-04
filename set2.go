package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
