package cryptopals

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestC9(t *testing.T) {
	a := assert.New(t)

	actual := PKCS7Pad([]byte("YELLOW SUBMARINE"), 20)
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")
	a.Equal(expected, actual)
}

/*
func TestC10(t *testing.T) {
	a := assert.New(t)

	b, err := ioutil.ReadFile("10.txt")
	a.NoError(err)

	key := []byte("YELLOW SUBMARINE")
	iv := bytes.Repeat([]byte{byte(0)}, 16)
	fmt.Println(string(CBCDecrypt(b, key, iv)))
}
*/
