package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// HexToBase64 takes a hex encoded byte array and returns a base 64 encoded
// byte array, a function that only operates upon a byte repr is desirable
// in terms of effiency
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

// Xor takes two equal length buffers and returns their XOR combination
func Xor(b1, b2 []byte) []byte {
	l := len(b1)
	if len(b2) != l {
		panic(fmt.Sprintf("Xor does not accept unequal length args len(b1)=%d, len(b2)=%d",
			len(b1), len(b2)))
	}
	out := make([]byte, l)
	for i := 0; i < l; i++ {
		out[i] = b1[i] ^ b2[i]
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
		bIn2 := make([]byte, len(bIn1))
		for j := 0; j < len(bIn1); j++ {
			bIn2[j] = byte(i)
		}
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
