package cryptopals

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"strings"
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

func TestC3(t *testing.T) {
	a := assert.New(t)

	in := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	bIn1, err := hex.DecodeString(in)
	a.NoError(err)
	r := BruteforceXOR(bIn1)
	a.Equal("Cooking MC's like a pound of bacon", r.Plaintext)
}

func TestC4(t *testing.T) {
	a := assert.New(t)

	b, err := ioutil.ReadFile("data/4.txt")
	a.NoError(err)

	lines := strings.Split(string(b), "\n")
	topResult := &Result{}
	for _, s := range lines {
		bIn, err := hex.DecodeString(s)
		a.NoError(err)
		result := BruteforceXOR(bIn)
		if result.Score > topResult.Score {
			topResult = result
		}
	}
	a.Equal("Now that the party is jumping\n", topResult.Plaintext)
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

var iceBytes, _ = ioutil.ReadFile("data/ice.txt")
var icePlaintext = string(iceBytes)

func TestC6(t *testing.T) {
	a := assert.New(t)

	// Read Data
	b64, err := ioutil.ReadFile("data/6.txt")
	a.NoError(err)

	// Decode from base64
	b, err := Base64Decode(b64)
	a.NoError(err)
	plaintext := string(BreakRepeatingKeyXOR(b))
	a.True(strings.HasPrefix(plaintext, icePlaintext))
}

func TestC7(t *testing.T) {
	a := assert.New(t)

	b64, err := ioutil.ReadFile("data/7.txt")
	a.NoError(err)

	b, err := Base64Decode(b64)
	a.NoError(err)

	key := []byte("YELLOW SUBMARINE")
	actualPlaintext := DecryptAESECB(b, key)

	a.True(strings.HasPrefix(string(actualPlaintext), icePlaintext))
}

func TestC8(t *testing.T) {
	a := assert.New(t)

	b, err := ioutil.ReadFile("data/8.txt")
	a.NoError(err)

	lines := bytes.Split(bytes.Trim(b, "\n"), []byte("\n"))

	for lineNo, line := range lines {
		detected := DetectECB(line)
		if detected {
			a.Equal(132, lineNo)
		} else {
			a.NotEqual(132, lineNo)
		}
	}
}
