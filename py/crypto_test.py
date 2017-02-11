import base64
import crypto
import unittest


class HammingDistance(unittest.TestCase):

    def runTest(self):
        b1 = b"this is a test"
        b2 = b"wokka wokka!!!"
        self.assertEqual(37.0, crypto.hamming_distance(b1, b2))
        self.assertEqual(
            (37 * 4.0) / 6, crypto.hamming_distance(b1, b2, b1, b2))
        self.assertEqual(
            (37 * 4.0) / 6, crypto.hamming_distance(b1, b1, b2, b2))
        self.assertEqual(0.0, crypto.hamming_distance(b1, b1, b1))


class DetermineKeysize(unittest.TestCase):

    def runTest(self):
        with open("../data/6.txt") as f:
            b64 = f.read()
        b = base64.b64decode(b64)
        keysize, _ = crypto.determine_keysize(b)
        self.assertEqual(29, keysize)


unittest.main()
