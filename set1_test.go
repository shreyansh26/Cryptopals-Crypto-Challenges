package cryptopals

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"testing"
)

func hexDecode(t *testing.T, s string) []byte {
	v, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("failed to decode hex: ", s)
	}
	return v
}

func corpusFromFile(t *testing.T, name string) map[rune]float64 {
	text, err := ioutil.ReadFile(name)
	if err != nil {
		t.Fatal("failed to open corpus file", err)
	}
	return buildCorpus(string(text))
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

func TestProblem3(t *testing.T) {
	c := corpusFromFile(t, "data/aliceinwonderland.txt")
	decoded := hexDecode(t, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	key := findSingleXORKey(decoded, c)
	t.Logf("Key: %c\n", key)
	t.Logf(string(singleXOR(decoded, key)))
}
