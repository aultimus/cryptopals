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

	keysize, distance := cryptopals.DetermineKeysize(b)
	fmt.Printf("Likely keysize %d has normalised hamming distance of %f\n",
		keysize, distance)

	blocks := makeBlocks(b, keysize, keysize)
	transposed := transposeBlocks(blocks)

	cypher := make([]byte, keysize)
	for i, block := range transposed {
		result := cryptopals.BruteforceXOR(block)
		cypher[i] = byte(result.Cypher)
	}

	plaintext := string(cryptopals.Xor(b, cypher))
	fmt.Println(plaintext)
}

// TODO: test
func transposeBlocks(blocks [][]byte) [][]byte {
	l := len(blocks)
	if l != len(blocks[0]) {
		panic(fmt.Sprintf("unable to transpose non square matrix (%d by %d)",
			l, len(blocks[0])))
	}
	transposed := make([][]byte, l)
	for i := 0; i < l; i++ {
		transposed[i] = make([]byte, l)
	}

	for i := 0; i < l; i++ {
		for j := 0; j < l; j++ {
			transposed[i][j] = blocks[j][i]
		}
	}
	return transposed
}

// TODO: test
func makeBlocks(b []byte, blocksize, numBlocks int) [][]byte {
	// make blocksize blocks of blocksize length
	blocks := make([][]byte, numBlocks)
	for i := 0; i < numBlocks; i++ {
		blocks[i] = make([]byte, blocksize)
		blocks[i] = b[blocksize*i : (blocksize*i)+blocksize]
	}
	return blocks
}
