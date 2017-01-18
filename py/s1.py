import binascii
import crypto
import unittest


class C1(unittest.TestCase):
	def runTest(self):
		hex_str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
		expected = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t\n"
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

unittest.main()