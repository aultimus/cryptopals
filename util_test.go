package cryptopals

import (
	"encoding/hex"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestC1(t *testing.T) {
	a := assert.New(t)

	hStr := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	actual := HexStringToBase64String(hStr)
	a.Equal(actual, expected)
}

func TestC2(t *testing.T) {
	a := assert.New(t)

	in1 := "1c0111001f010100061a024b53535009181c"
	in2 := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"

	bIn1, err := hex.DecodeString(in1)
	a.NoError(err)

	bIn2, err := hex.DecodeString(in2)
	a.NoError(err)

	bOut := Xor(bIn1, bIn2)
	actual := hex.EncodeToString(bOut)
	a.Equal(expected, actual)
}

func TestC5(t *testing.T) {
	a := assert.New(t)

	in1 := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	in2 := "ICE"

	expected := `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`

	actualBytes := Xor([]byte(in1), []byte(in2))
	actualStr := hex.EncodeToString(actualBytes)
	a.Equal(expected, actualStr)
}

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

	b64, err := ioutil.ReadFile("s1c6/6.txt")
	if err != nil {
		panic(err.Error())
	}

	// Decode from base64
	b, err := Base64Decode(b64)
	if err != nil {
		panic(err.Error())
	}

	keysize, _ := DetermineKeysize(b)
	a.Equal(29, keysize)
}
