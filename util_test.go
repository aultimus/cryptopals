package cryptopals

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHammingDistance(t *testing.T) {
	a := assert.New(t)
	b1 := []byte("this is a test")
	b2 := []byte("wokka wokka!!!")
	a.Equal(37.0, HammingDistance(b1, b2))
	a.Equal((37*4.0)/6, HammingDistance(b1, b2, b1, b2))
	a.Equal((37*4.0)/6, HammingDistance(b1, b1, b2, b2))
	a.Equal(0.0, HammingDistance(b1, b1, b1))
}

func TestDetermineKeysize(t *testing.T) {
	a := assert.New(t)

	b64, err := ioutil.ReadFile("data/6.txt")
	a.NoError(err)

	// Decode from base64
	b, err := Base64Decode(b64)
	a.NoError(err)

	keysize, _ := DetermineKeysize(b)
	a.Equal(29, keysize)
}

func TestAESECBEncryptDecrypt(t *testing.T) {
	a := assert.New(t)

	key := []byte("QWERTYASDFGZXCVB")
	a.Equal(16, len(key))
	plaintext := "Everywhere he goes, Bodger always knows, Badger and his Badger mates are never far away!... Bodger and Badger! Bodger and Badger! La la la la la Badgers never far away..! Everybody knows, Badger loves, Mash Potato! He makes them into shapes and eats them everyday…! Bodger and Badger! Bodger and badger! La la la la la, la la la la la, Everywhere he goes, Bodger always knows, Badger and his Badger mates are never far away..! Bodger and Badger! Bodger and Badger! La la la la la, la la la la la. Bodger and Badger are never far away!"
	b := PKCS7Pad([]byte(plaintext), len(key))

	cipherText := EncryptAESECB(b, key)
	a.Equal(b, PKCS7Pad([]byte(plaintext), len(key)),
		"encrypt shouldn't change contents")
	a.NotEqual(plaintext, string(cipherText))
	decryptedText := DecryptAESECB(cipherText, key)
	a.Equal(b, PKCS7Pad([]byte(plaintext), len(key)),
		"decrypt shouldn't change contents")
	a.Equal(plaintext, string(decryptedText))
}

func testPadding(a *assert.Assertions, b []byte) {
	blockSize := 16
	padSize := blockSize - len(b)%blockSize
	expectedPad := append(b, bytes.Repeat([]byte{byte(padSize)}, padSize)...)
	padActual := PKCS7Pad(b, blockSize)
	a.Equal(expectedPad, padActual)
	unpadActual := PKCS7Unpad(padActual, blockSize)
	a.Equal(b, unpadActual)
}

func TestPKCS7PadUnpad(t *testing.T) {
	a := assert.New(t)

	testPadding(a, []byte("woke up this morning, feeling blue"))
	byOne := []byte("blue in my belly, blue in my se")
	a.Equal(15, len(byOne)%16)
	testPadding(a, byOne)
}

func TestAESCBCEncryptDecrypt(t *testing.T) {
	a := assert.New(t)

	expectedPlaintext := "Everywhere he goes, Bodger always knows, Badger and his Badger mates are never far away!... Bodger and Badger! Bodger and Badger! La la la la la Badgers never far away..! Everybody knows, Badger loves, Mash Potato! He makes them into shapes and eats them everyday…! Bodger and Badger! Bodger and badger! La la la la la, la la la la la, Everywhere he goes, Bodger always knows, Badger and his Badger mates are never far away..! Bodger and Badger! Bodger and Badger! La la la la la, la la la la la. Bodger and Badger are never far away!"
	key := []byte("QWERTYASDFGZXCVB")
	iv := bytes.Repeat([]byte{byte(0)}, 16)
	a.Equal(16, len(key))
	a.Equal(16, len(iv))

	cipherText := CBCEncrypt([]byte(expectedPlaintext), key, iv)

	actualPlaintext := CBCDecrypt(cipherText, key, iv)
	a.Equal(expectedPlaintext, string(actualPlaintext))
}
