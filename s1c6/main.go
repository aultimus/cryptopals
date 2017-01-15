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

	plaintext := string(cryptopals.BreakRepeatingKeyXOR(b))
	fmt.Println(plaintext)
}
