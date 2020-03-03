package cryptopals

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"log"
	"math"
	"math/bits"
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

func repeatingKeyXOR(text []byte, key []byte) []byte {
	res := make([]byte, len(text))
	for i := range text {
		res[i] = text[i] ^ key[i%len(key)]
	}
	return res
}

func getHammingDistance(text1 []byte, text2 []byte) int {
	if len(text1) != len(text2) {
		panic("hammingDistance: different lengths")
	}
	distance := 0
	for i := range text1 {
		if text1[i] != text2[i] {
			distance += bits.OnesCount8(text1[i] ^ text2[i])
		}
	}
	return distance
}

func findrepeatingKeyXORSize(in []byte) int {
	var res int
	bestScore := math.MaxFloat64
	for keyLen := 2; keyLen < 40; keyLen++ {
		a, b := in[:keyLen*4], in[keyLen*4:keyLen*4*2]
		score := float64(getHammingDistance(a, b)) / float64(keyLen)
		if score < bestScore {
			bestScore = score
			res = keyLen
		}
	}
	return res
}

func findrepeatingKeyXORKey(in []byte, c map[rune]float64) []byte {
	keySize := findrepeatingKeyXORSize(in)
	column := make([]byte, (len(in)+keySize-1)/keySize)
	key := make([]byte, keySize)

	for col := 0; col < keySize; col++ {
		for row := range column {
			if row*keySize+col >= len(in) {
				continue
			}
			column[row] = in[row*keySize+col]
		}
		_, k, _ := findSingleXORKey(column, c)
		key[col] = k
	}
	return key
}

func decryptAESECB(text []byte, b cipher.Block) []byte {
	if len(text)%b.BlockSize() != 0 {
		panic("decryptAESECB: length not a multiple of BlockSize")
	}
	out := make([]byte, len(text))
	for i := 0; i < len(text); i += b.BlockSize() {
		b.Decrypt(out[i:], text[i:])
	}
	return out
}

func detectAESECB(in []byte, blockSize int) bool {
	if len(in)%blockSize != 0 {
		panic("decryptAESECB: length not a multiple of blockSize")
	}
	seen := make(map[string]struct{})
	for i := 0; i < len(in); i += blockSize {
		val := string(in[i : i+blockSize])
		if _, ok := seen[val]; ok {
			return true
		}
		seen[val] = struct{}{}
	}
	return false
}
