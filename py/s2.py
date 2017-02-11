import crypto
import unittest


class C9(unittest.TestCase):

    def runTest(self):
        actual = crypto.pkcs7pad(b"YELLOW SUBMARINE", 20)
        expected = b"YELLOW SUBMARINE\x04\x04\x04\x04"
        self.assertEqual(expected, actual)

unittest.main()
