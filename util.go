package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Base64Decode decodes a byte array from base64 encoding
// Seems to be returning too long a slice for s1c6
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
	Cypher    byte
	Score     float64
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
			Cypher:    bIn2[0],
			Score:     ScorePlaintext(s),
		}
		if r.Score > topResult.Score {
			topResult = r
		}
	}
	return topResult

}

// Source http://www.data-compression.com/english.html
var letterFrequency = map[string]float64{
	"a": 0.0651738,
	"b": 0.0124248,
	"c": 0.0217339,
	"d": 0.0349835,
	"e": 0.1041442,
	"f": 0.0197881,
	"g": 0.0158610,
	"h": 0.0492888,
	"i": 0.0558094,
	"j": 0.0009033,
	"k": 0.0050529,
	"l": 0.0331490,
	"m": 0.0202124,
	"n": 0.0564513,
	"o": 0.0596302,
	"p": 0.0137645,
	"q": 0.0008606,
	"r": 0.0497563,
	"s": 0.0515760,
	"t": 0.0729357,
	"u": 0.0225134,
	"v": 0.0082903,
	"w": 0.0171272,
	"x": 0.0013692,
	"y": 0.0145984,
	"z": 0.0007836,
	" ": 0.1918182,
}

// ScorePlaintext scores a string for confidence that is plaintext, the higher the score,
// the higher the confidence
func ScorePlaintext(s string) float64 {
	var total float64
	for i := 0; i < len(s); i++ {
		total += letterFrequency[string(s[i])]
	}
	return total
}

func HammingDistance(bs ...[]byte) float64 {
	var total float64
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
	total /= float64(numIter)
	return total
}

func hammingDistanceImpl(b1, b2 []byte) float64 {
	if len(b1) != len(b2) {
		panic(fmt.Sprintf("hammingDistanceImpl called with different length buffers len(b1)=%d, len(b2)=%d",
			len(b1), len(b2)))
	}

	var total float64
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

// DetermineKeysize determines the likely keysize of an encryption cypher
// given the encrypted data b. It also returns normalised difference of the
// blocks of size keysize, this can be considered a sort of confidence, the
// lower the better
func DetermineKeysize(b []byte) (int, float64) {
	// TODO: Refactor out into a function
	// Determine keysize
	shortestDistance := 1000.0 // suitably large
	likelyKeysize := -1
	for keysize := 2; keysize < 41; keysize++ {
		b1 := b[:keysize]
		b2 := b[keysize : keysize*2]
		b3 := b[keysize*2 : keysize*3]
		b4 := b[keysize*3 : keysize*4]
		normDistance := HammingDistance(b1, b2, b3, b4) / float64(keysize)
		//fmt.Printf("keysize %d, distance %f\n", keysize, normDistance)
		if normDistance < shortestDistance {
			shortestDistance = normDistance
			likelyKeysize = keysize
		}
	}
	return likelyKeysize, shortestDistance
}

//BreakRepeatingKeyXOR ...
func BreakRepeatingKeyXOR(b []byte) []byte {
	keysize, distance := DetermineKeysize(b)
	fmt.Printf("Likely keysize %d has normalised hamming distance of %f\n",
		keysize, distance)

	blocks := makeBlocks(b, keysize, keysize)
	transposed := transposeBlocks(blocks)

	cypher := make([]byte, keysize)
	for i, block := range transposed {
		result := BruteforceXOR(block)
		cypher[i] = byte(result.Cypher)
	}

	return Xor(b, cypher)
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

// DecryptAESECB decrypts encrypted data b using given key
// Equivalent in openssl commandline:
// fmt.Sprintf(openssl enc -aes-128-ecb -a -d -K '%s' -nosalt -in 7.txt", hex.EncodeToString(key))
func DecryptAESECB(b, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	if aes.BlockSize != len(key) {
		panic(err.Error())
	}

	mode := NewECBDecrypter(block)
	mode.CryptBlocks(b, b)
	return PKCS7Unpad(b, len(key))

}

// EncryptAESECB encrypts data b using given key
func EncryptAESECB(b, key []byte) []byte {
	// Take a copy as we need to return a copy as we may enlarge
	// and therefore it is unecessary to alter original data
	d := make([]byte, len(b))
	copy(d, b)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	if aes.BlockSize != len(key) {
		panic(err.Error())
	}

	if len(d)%len(key) != 0 {
		// add padding
		d = PKCS7Pad(d, len(key))
	}

	mode := NewECBEncrypter(block)
	mode.CryptBlocks(d, d)
	return d
}

// DetectECB detects if ciphertext b is encrypted via ECB
func DetectECB(b []byte) bool {
	// Assume 128 bit encryption
	blockSize := 16

	// Look for repeated sequences of size blockSize
	// We are assuming that the plaintext has repetitions of at least
	// 16 Bytes
	for i := 0; i < len(b)-blockSize; i++ {
		currentBlock := b[i : i+blockSize]
		if bytes.Count(b, currentBlock) > 1 {
			return true
		}
	}
	return false
}

// PKCS7Pad pads data b upto nearest multiple of blocksize
// PKCS#7 padding should work for any block size from 1 to 255 bytes
func PKCS7Pad(b []byte, blockSize int) []byte {
	if blockSize < 1 || blockSize > 255 {
		panic(fmt.Sprintf("PKCS7Pad unsupported blocksize %d", blockSize))
	}

	// pad the input at the trailing end with k - (l mod k) octets all having
	// value k - (l mod k), where l is the length of the input, and k the block
	// size.
	padAmount := blockSize - len(b)%blockSize
	fmt.Printf("adding %d bytes of padding\n", padAmount)
	padVal := []byte{byte(padAmount)}
	padding := bytes.Repeat(padVal, padAmount)
	return append(b, padding...)
}

// PKCS7Unpad strips padding from unencrypted data b
func PKCS7Unpad(b []byte, blockSize int) []byte {
	if blockSize < 1 || blockSize > 255 {
		panic(fmt.Sprintf("PKCS7Unpad unsupported blocksize %d", blockSize))
	}
	if len(b)%blockSize != 0 {
		panic("PKCS7Unpad b % blocksize != 0")
	}

	padVal := int(b[len(b)-1])
	if padVal == 1 {
		fmt.Println("stripping 1 byte of padding")
		return b[:len(b)-1]
	}

	if padVal != int(b[len(b)-2]) {
		fmt.Println("No padding to remove")
		return b
	}

	// verify padding is as expected
	for i := 2; i < padVal; i++ {
		val := b[len(b)-i]
		if val != byte(padVal) {
			panic(fmt.Sprintf("unexpected non-padding %v, expected %v",
				val, byte(padVal)))
		}
	}
	fmt.Printf("stripping %d bytes of padding\n", padVal)
	return b[:len(b)-padVal]
}
