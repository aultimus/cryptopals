import base64
import binascii
import crypto
import unittest


class C1(unittest.TestCase):

    def runTest(self):
        hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206" \
            "120706f69736f6e6f7573206d757368726f6f6d"
        expected = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG1" \
            b"1c2hyb29t\n"
        b = binascii.unhexlify(hex_str)
        actual = binascii.b2a_base64(b)
        self.assertEqual(actual, expected)


class C2(unittest.TestCase):

    def runTest(self):
        in1 = "1c0111001f010100061a024b53535009181c"
        in2 = "686974207468652062756c6c277320657965"
        expected = bytearray.fromhex("746865206b696420646f6e277420706c6179")

        bIn1 = binascii.unhexlify(in1)
        bIn2 = binascii.unhexlify(in2)
        actual = crypto.xor(bIn1, bIn2)
        self.assertEqual(actual, expected)


class C3(unittest.TestCase):

    def runTest(self):
        bIn = bytes.fromhex("1b37373331363f78151b7f2b783431333d783978283"
                            "72d363c78373e783a393b3736")
        r = crypto.bruteforce_xor(bIn)
        self.assertEqual("Cooking MC's like a pound of bacon", r.plaintext)


class C4(unittest.TestCase):

    def runTest(self):
        with open("../data/4.txt") as f:
            lines = f.readlines()

        top_result = crypto.Result("", bytes(), 0)
        for l in lines:
            l = l.rstrip("\n")
            b = bytes.fromhex(l)
            result = crypto.bruteforce_xor(b)
            if result.score > top_result.score:
                top_result = result
        self.assertEqual("Now that the party is jumping\n",
                         top_result.plaintext)


class C5(unittest.TestCase):

    def runTest(self):
        in1 = b"Burning 'em, if you ain't quick and nimble\n" \
              b"I go crazy when I hear a cymbal"
        in2 = b"ICE"
        expected = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343" \
                   b"c2a26226324272765272a282b2f20430a652e2c652a3124333a653e" \
                   b"2b2027630c692b20283165286326302e27282f"
        actual_bytes = crypto.xor(in1, in2)
        actual_hex = binascii.hexlify(actual_bytes)
        self.assertEqual(expected, actual_hex)

with open("../data/ice.txt") as f:
    ice_plaintext = f.read()


class C6(unittest.TestCase):

    def runTest(self):
        with open("../data/6.txt") as f:
            b64 = f.read()
        b = base64.b64decode(b64)
        plaintext = crypto.break_repeating_key_xor(b).decode()
        self.assertEqual(plaintext, ice_plaintext)

unittest.main()
