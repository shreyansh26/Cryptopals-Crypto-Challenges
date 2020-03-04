package cryptopals

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
