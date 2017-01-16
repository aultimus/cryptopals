package cryptopals

import (
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHammingDistance(t *testing.T) {
	a := assert.New(t)
	b1 := []byte("this is a test")
	b2 := []byte("wokka wokka!!!")
	a.Equal(37.0, HammingDistance(b1, b2))
	a.Equal((37*4.0)/6, HammingDistance(b1, b2, b1, b2))
	a.Equal((37*4.0)/6, HammingDistance(b1, b1, b2, b2))
	a.Equal(0.0, HammingDistance(b1, b1, b1))
}

func TestDetermineKeysize(t *testing.T) {
	a := assert.New(t)

	b64, err := ioutil.ReadFile("6.txt")
	a.NoError(err)

	// Decode from base64
	b, err := Base64Decode(b64)
	a.NoError(err)

	keysize, _ := DetermineKeysize(b)
	a.Equal(29, keysize)
}
