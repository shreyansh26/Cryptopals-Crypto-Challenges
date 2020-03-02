package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"log"
	"unicode/utf8"
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

func buildCorpus(text string) map[rune]float64 {
	c := make(map[rune]float64)
	for _, char := range text {
		c[char] = c[char] + 1
	}
	total := utf8.RuneCountInString(text)
	for char := range c {
		c[char] = c[char] / float64(total)
	}
	return c
}

func scoreEnglishText(text string, c map[rune]float64) float64 {
	var score float64
	for _, char := range text {
		score += c[char]
	}
	return score / float64(utf8.RuneCountInString(text))
}

func singleXOR(in []byte, key byte) []byte {
	res := make([]byte, len(in))
	for i, c := range in {
		res[i] = c ^ key
	}
	return res
}

func findSingleXORKey(in []byte, c map[rune]float64) ([]byte, byte, float64) {
	var lastMaxScore = 0.0
	var res byte
	var ans []byte
	for key := 0; key < 256; key++ {
		out := singleXOR(in, byte(key))
		score := scoreEnglishText(string(out), c)

		if score > lastMaxScore {
			res = byte(key)
			lastMaxScore = score
			ans = out
		}
	}
	return ans, res, lastMaxScore
}

func repeatingKeyXOR(text []byte, key string) []byte {
	res := make([]byte, len(text))
	for i := range text {
		res[i] = text[i] ^ key[i%len(key)]
	}
	return res
}
