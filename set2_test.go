package cryptopals

import (
	"bytes"
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
