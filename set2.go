package cryptopals

import "crypto/cipher"

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
