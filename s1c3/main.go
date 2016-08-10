package main

import (
	"encoding/hex"

	"github.com/aultimus/cryptopals"
	"github.com/davecgh/go-spew/spew"
)

type result struct {
	plaintext string
	cypher    int
	score     int
}

func main() {

	in := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	bIn1, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}
	var scores = make([]*result, 255, 255)
	// cycle through possible cyphers
	for i := 0; i < 255; i++ {
		// construct equal sized cypher array for passing to Xor
		bIn2 := make([]byte, len(bIn1))
		for j := 0; j < len(bIn1); j++ {
			bIn2[j] = byte(i)
		}
		s := hex.EncodeToString(cryptopals.Xor(bIn1, bIn2))
		scores[i] = &result{
			plaintext: s,
			cypher:    i,
			score:     score(s),
		}
	}
	spew.Dump(scores)

}

func score(s string) int {
	var c int
	for i := 0; i < len(s); i++ {
		ch := s[i]
		for n := 0; n < 10; n++ {
			if ch == string(n) { // strconv probably
				c--
				break
			}
		}
	}
	return c
}
