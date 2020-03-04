package cryptopals

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestProblem9(t *testing.T) {
	if res := padPKCS7([]byte("YELLOW SUBMARINE"), 16); !bytes.Equal(res, []byte("YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10")) {
		t.Errorf("%q", res)
	}
	if res := padPKCS7([]byte("YELLOW SUBMARINE"), 20); !bytes.Equal(res, []byte("YELLOW SUBMARINE\x04\x04\x04\x04")) {
		t.Errorf("%q", res)
	}
}

func TestProblem10(t *testing.T) {
	msg := []byte("YELLOW SUBMARINEYELLOW SUBMARINE")
	iv := make([]byte, 16)
	b, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	res := decryptCBC(encryptCBC(msg, b, iv), b, iv)
	if !bytes.Equal(res, msg) {
		t.Errorf("%q", res)
	}

	data := decodeBase64(t, string(readFile(t, "data/10.txt")))
	decoded := decryptCBC(data, b, iv)
	t.Logf("Result: %s", decoded)
}
