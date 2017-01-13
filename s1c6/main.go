package main

import (
	"fmt"
	"io/ioutil"

	"github.com/aultimus/cryptopals"
)

func main() {
	// Read Data
	b64, err := ioutil.ReadFile("6.txt")
	if err != nil {
		panic(err.Error())
	}

	// Decode from base64
	b, err := cryptopals.Base64Decode(b64)
	if err != nil {
		panic(err.Error())
	}

	// Determine keysize
	shortestDistance := 1000.0 // suitably large
	likelyKeysize := -1
	for keysize := 2; keysize < 41; keysize++ {
		b1 := b[:keysize]
		b2 := b[keysize : keysize*2]
		b3 := b[keysize*2 : keysize*3]
		b4 := b[keysize*3 : keysize*4]
		normDistance := cryptopals.HammingDistance(b1, b2, b3, b4) / float64(keysize)
		//fmt.Printf("keysize %d, distance %f\n", keysize, normDistance)
		if normDistance < shortestDistance {
			shortestDistance = normDistance
			likelyKeysize = keysize
		}
	}
	fmt.Printf("Likely keysize %d has normalised hamming distance of %f\n", likelyKeysize, shortestDistance)
}
