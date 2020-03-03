package cryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"
)

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := ioutil.ReadFile(name)
	if err != nil {
		t.Fatal("failed to read file:", err)
	}
	return data
}

func hexDecode(t *testing.T, s string) []byte {
	v, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("failed to decode hex: ", s)
	}
	return v
}

func corpusFromFile(name string) map[rune]float64 {
	text, err := ioutil.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintln("failed to read corpus file:", err))
	}
	return buildCorpus(string(text))
}

func decodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	v, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal("failed to decode base64:", s)
	}
	return v
}

func TestProblem1(t *testing.T) {
	res, err := hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
	if err != nil {
		t.Fatal(err)
	}
	if res != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Errorf("wrong string %s", res)
	}
}

func TestProblem2(t *testing.T) {
	res := xor(hexDecode(t, "1c0111001f010100061a024b53535009181c"), hexDecode(t, "686974207468652062756c6c277320657965"))

	if !bytes.Equal(res, hexDecode(t, "746865206b696420646f6e277420706c6179")) {
		t.Errorf("wrong string %x", res)
	}
}

var corpus = corpusFromFile("data/aliceinwonderland.txt")

func TestProblem3(t *testing.T) {
	decoded := hexDecode(t, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	decrypted, key, _ := findSingleXORKey(decoded, corpus)
	t.Logf("Key: %c\n", key)
	t.Logf("Decrypted: %s", string(decrypted))
}

func TestProblem4(t *testing.T) {
	text := readFile(t, "data/4.txt")

	var maxScore float64
	var cipher string
	var plaintext []byte
	for _, line := range strings.Split(string(text), "\n") {
		plain, _, score := findSingleXORKey(hexDecode(t, line), corpus)
		if score > maxScore {
			cipher = line
			plaintext = plain
			maxScore = score
		}
	}
	t.Logf("Ciphertext: %s\n", cipher)
	t.Logf("Plaintext: %s\n", plaintext)
}

func TestProblem5(t *testing.T) {
	text := readFile(t, "data/5.txt")
	res := repeatingKeyXOR(text, []byte("ICE"))
	if !bytes.Equal(res, hexDecode(t, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")) {
		t.Errorf("wrong result: %x", res)
	}
	t.Logf("Result: %x\n", res)
}

func TestProblem6(t *testing.T) {
	distance := getHammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	if distance != 37 {
		t.Errorf("wrong Hamming distance: %d", distance)
	}

	text := decodeBase64(t, string(readFile(t, "data/6.txt")))
	t.Log("likely size: ", findrepeatingKeyXORSize(text))

	key := findrepeatingKeyXORKey(text, corpus)
	t.Logf("likely key: %q", key)

	t.Logf("Result: %s", repeatingKeyXOR(text, key))
}
