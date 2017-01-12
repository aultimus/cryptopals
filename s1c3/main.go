package main

import (
	"encoding/hex"
	"strings"

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
	topResult := &result{}
	n := 128
	// cycle through possible cyphers
	for i := 0; i < n; i++ {
		// construct equal sized cypher array for passing to Xor
		bIn2 := make([]byte, len(bIn1))
		for j := 0; j < len(bIn1); j++ {
			bIn2[j] = byte(i)
		}
		s := string(cryptopals.Xor(bIn1, bIn2))
		r := &result{
			plaintext: s,
			cypher:    i,
			score:     score(s),
		}
		if r.score > topResult.score {
			topResult = r
		}
	}
	spew.Dump(topResult)
}

func score(s string) int {
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
