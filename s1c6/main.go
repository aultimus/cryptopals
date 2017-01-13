package main

import (
	"fmt"
	"io/ioutil"

	"github.com/aultimus/cryptopals"
)

func main() {
	b64, err := ioutil.ReadFile("6.txt")
	if err != nil {
		panic(err.Error())
	}

	b, err := cryptopals.Base64Decode(b64)
	if err != nil {
		panic(err.Error())
	}

	shortestDistance := 1000 // suitably large
	likelyKeysize := -1
	for keysize := 2; keysize < 41; keysize++ {
		b1 := b[:keysize]
		b2 := b[keysize : keysize*2]
		normDistance := cryptopals.HammingDistance(b1, b2) / keysize
		if normDistance < shortestDistance {
			shortestDistance = normDistance
			likelyKeysize = keysize
		}
	}
	fmt.Printf("Likely keysize %d has normalised hamming distance of %d\n", likelyKeysize, shortestDistance)
}
