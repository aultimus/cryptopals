package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Base64Decode decodes a byte array from base64 encoding
func Base64Decode(src []byte) ([]byte, error) {
	b := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	_, err := base64.StdEncoding.Decode(b, src)
	return b, err
}

// HexToBase64 takes a hex encoded byte array and returns a base 64 encoded
// byte array, a function that only operates upon a byte repr is desirable
// in terms of effiency
// TODO: This is not hex specific, rename Base64Encode
func HexToBase64(src []byte) []byte {
	// so the different representations - hex and base64 take up different
	// amounts of bytes
	dest := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	base64.StdEncoding.Encode(dest, src)
	return dest
}

// HexStringToBase64String is a utility function, not intended for heavy use
// due to string conversions
func HexStringToBase64String(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	b64 := HexToBase64(b)
	return string(b64)
}

// Xor takes two buffers and returns their XOR combination
// b2 can be shorter in length than b1, if so b2 will repeat
func Xor(b1, b2 []byte) []byte {
	l := len(b1)
	if len(b2) > l {
		panic(fmt.Sprintf("Xor does not accept b2 longer than b1, args len(b1)=%d, len(b2)=%d",
			len(b1), len(b2)))
	}
	out := make([]byte, l)
	b2Index := 0
	for i := 0; i < l; i++ {
		out[i] = b1[i] ^ b2[b2Index]
		b2Index++
		if b2Index == len(b2) {
			b2Index = 0
		}
	}
	return out
}

type Result struct {
	Plaintext string
	Cypher    int
	Score     int
}

// BruteforceXOR searches for a single character XOR cypher that yields the
// most likely plaintext
func BruteforceXOR(bIn1 []byte) *Result {
	topResult := &Result{}
	// cycle through possible cyphers
	for i := 0; i < 128; i++ {
		// construct equal sized cypher array for passing to Xor
		bIn2 := []byte{byte(i)}
		s := string(Xor(bIn1, bIn2))
		r := &Result{
			Plaintext: s,
			Cypher:    i,
			Score:     ScorePlaintext(s),
		}
		if r.Score > topResult.Score {
			topResult = r
		}
	}
	return topResult

}

// ScorePlaintext scores a string for confidence that is plaintext, the higher the score,
// the higher the confidence
func ScorePlaintext(s string) int {
	popular := "uldrhsnioate" // "etaoinshrdlu" // reversed

	var total int
	for i := 0; i < len(s); i++ {
		subscore := strings.Index(popular, string(s[i]))
		if subscore != -1 {
			total += subscore
		}
	}
	return total
}

func HammingDistance(bs ...[]byte) int {
	var total int
	if len(bs) < 2 {
		panic(fmt.Sprintf("HammingDistanceAverage called with only %d args, requires at least 2",
			len(bs)))
	}
	var numIter int
	for i := 0; i < len(bs); i++ {
		for j := i + 1; j < len(bs); j++ {
			dist := hammingDistanceImpl(bs[i], bs[j])
			//fmt.Printf("%d %d has distance of %d\n", i, j, dist)
			total += dist
			numIter++
		}
	}
	total /= numIter
	return total
}

func hammingDistanceImpl(b1, b2 []byte) int {
	if len(b1) != len(b2) {
		panic(fmt.Sprintf("hammingDistanceImpl called with different length buffers len(b1)=%d, len(b2)=%d",
			len(b1), len(b2)))
	}

	var total int
	for i := 0; i < len(b1); i++ {
		// xor args, thus val represents the number of bits set
		val := b1[i] ^ b2[i]

		// increment total by one and clear a bit
		for val != 0 {
			total++
			val &= val - 1
		}
	}
	return total
}
