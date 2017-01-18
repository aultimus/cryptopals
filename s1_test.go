package cryptopals

import (
	"bytes"
	"encoding/hex"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestC1(t *testing.T) {
	a := assert.New(t)

	hStr := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	actual := HexStringToBase64String(hStr)
	a.Equal(actual, expected)
}

func TestC2(t *testing.T) {
	a := assert.New(t)

	in1 := "1c0111001f010100061a024b53535009181c"
	in2 := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"

	bIn1, err := hex.DecodeString(in1)
	a.NoError(err)

	bIn2, err := hex.DecodeString(in2)
	a.NoError(err)

	bOut := Xor(bIn1, bIn2)
	actual := hex.EncodeToString(bOut)
	a.Equal(expected, actual)
}

func TestC3(t *testing.T) {
	a := assert.New(t)

	in := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	bIn1, err := hex.DecodeString(in)
	a.NoError(err)
	r := BruteforceXOR(bIn1)
	a.Equal("Cooking MC's like a pound of bacon", r.Plaintext)
}

func TestC4(t *testing.T) {
	a := assert.New(t)

	b, err := ioutil.ReadFile("data/4.txt")
	a.NoError(err)

	lines := strings.Split(string(b), "\n")
	topResult := &Result{}
	for _, s := range lines {
		bIn, err := hex.DecodeString(s)
		a.NoError(err)
		result := BruteforceXOR(bIn)
		if result.Score > topResult.Score {
			topResult = result
		}
	}
	a.Equal("Now that the party is jumping\n", topResult.Plaintext)
}

func TestC5(t *testing.T) {
	a := assert.New(t)

	in1 := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	in2 := "ICE"

	expected := `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`

	actualBytes := Xor([]byte(in1), []byte(in2))
	actualStr := hex.EncodeToString(actualBytes)
	a.Equal(expected, actualStr)
}

var icePlaintext = `I'm back and I'm ringin' the bell 
A rockin' on the mike while the fly girls yell 
In ecstasy in the back of me 
Well that's my DJ Deshay cuttin' all them Z's 
Hittin' hard and the girlies goin' crazy 
Vanilla's on the mike, man I'm not lazy. 

I'm lettin' my drug kick in 
It controls my mouth and I begin 
To just let it flow, let my concepts go 
My posse's to the side yellin', Go Vanilla Go! 

Smooth 'cause that's the way I will be 
And if you don't give a damn, then 
Why you starin' at me 
So get off 'cause I control the stage 
There's no dissin' allowed 
I'm in my own phase 
The girlies sa y they love me and that is ok 
And I can dance better than any kid n' play 

Stage 2 -- Yea the one ya' wanna listen to 
It's off my head so let the beat play through 
So I can funk it up and make it sound good 
1-2-3 Yo -- Knock on some wood 
For good luck, I like my rhymes atrocious 
Supercalafragilisticexpialidocious 
I'm an effect and that you can bet 
I can take a fly girl and make her wet. 

I'm like Samson -- Samson to Delilah 
There's no denyin', You can try to hang 
But you'll keep tryin' to get my style 
Over and over, practice makes perfect 
But not if you're a loafer. 

You'll get nowhere, no place, no time, no girls 
Soon -- Oh my God, homebody, you probably eat 
Spaghetti with a spoon! Come on and say it! 

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino 
Intoxicating so you stagger like a wino 
So punks stop trying and girl stop cryin' 
Vanilla Ice is sellin' and you people are buyin' 
'Cause why the freaks are jockin' like Crazy Glue 
Movin' and groovin' trying to sing along 
All through the ghetto groovin' this here song 
Now you're amazed by the VIP posse. 

Steppin' so hard like a German Nazi 
Startled by the bases hittin' ground 
There's no trippin' on mine, I'm just gettin' down 
Sparkamatic, I'm hangin' tight like a fanatic 
You trapped me once and I thought that 
You might have it 
So step down and lend me your ear 
'89 in my time! You, '90 is my year. 

You're weakenin' fast, YO! and I can tell it 
Your body's gettin' hot, so, so I can smell it 
So don't be mad and don't be sad 
'Cause the lyrics belong to ICE, You can call me Dad 
You're pitchin' a fit, so step back and endure 
Let the witch doctor, Ice, do the dance to cure 
So come up close and don't be square 
You wanna battle me -- Anytime, anywhere 

You thought that I was weak, Boy, you're dead wrong 
So come on, everybody and sing this song 

Say -- Play that funky music Say, go white boy, go white boy go 
play that funky music Go white boy, go white boy, go 
Lay down and boogie and play that funky music till you die. 

Play that funky music Come on, Come on, let me hear 
Play that funky music white boy you say it, say it 
Play that funky music A little louder now 
Play that funky music, white boy Come on, Come on, Come on 
Play that funky music`

func TestC6(t *testing.T) {
	a := assert.New(t)

	// Read Data
	b64, err := ioutil.ReadFile("data/6.txt")
	a.NoError(err)

	// Decode from base64
	b, err := Base64Decode(b64)
	a.NoError(err)

	plaintext := string(BreakRepeatingKeyXOR(b))
	a.True(strings.HasPrefix(plaintext, icePlaintext))
}

func TestC7(t *testing.T) {
	a := assert.New(t)

	b64, err := ioutil.ReadFile("data/7.txt")
	a.NoError(err)

	b, err := Base64Decode(b64)
	a.NoError(err)

	key := []byte("YELLOW SUBMARINE")
	actualPlaintext := DecryptAESECB(b, key)

	a.True(strings.HasPrefix(string(actualPlaintext), icePlaintext))
}

func TestC8(t *testing.T) {
	a := assert.New(t)

	b, err := ioutil.ReadFile("data/8.txt")
	a.NoError(err)

	lines := bytes.Split(bytes.Trim(b, "\n"), []byte("\n"))

	for lineNo, line := range lines {
		detected := DetectECB(line)
		if detected {
			a.Equal(132, lineNo)
		} else {
			a.NotEqual(132, lineNo)
		}
	}
}
