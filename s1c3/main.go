package main

import (
	"encoding/hex"

	"github.com/aultimus/cryptopals"
	"github.com/davecgh/go-spew/spew"
)

func main() {
	in := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	bIn1, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}
	spew.Dump(cryptopals.BruteforceXOR(bIn1))
}
