package cryptopals

import (
	"encoding/hex"
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
