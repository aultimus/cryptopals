package main

import (
	"encoding/hex"
	"io/ioutil"
	"strings"

	"github.com/aultimus/cryptopals"
	"github.com/davecgh/go-spew/spew"
)

func main() {
	b, err := ioutil.ReadFile("4.txt")
	if err != nil {
		panic(err.Error())
	}
	a := strings.Split(string(b), "\n")
	topResult := &cryptopals.Result{}
	for _, s := range a {
		bIn, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
		result := cryptopals.BruteforceXOR(bIn)
		if result.Score > topResult.Score {
			topResult = result
		}
	}
	spew.Dump(topResult)
}
