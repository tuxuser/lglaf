import env
from binascii import unhexlify
from laf_crypto import LafCrypto
import unittest


class TestCrypto(unittest.TestCase):
    def setUp(self):
        self.key = b'qndiakxxuiemdklseqid~a~niq,zjuxl'

    def test_transform(self):
        transformed = LafCrypto.key_transform(self.key)
        self.assertEqual(transformed, b'dqoev)ohnsWu\\bk`oiicmZ_lpqe\\ealp')

    def test_xor_key(self):
        transformed_key = b'dqoev)ohnsWu\\bk`oiicmZ_lpqe\\ealp'
        challenge = unhexlify(b'f29ae130')
        xored_key = LafCrypto.xor_key(transformed_key, challenge)
        self.assertEqual(xored_key, b'T\x90\xf5\x97F\xc8\xf5\x9a^\x92\xcd\x87l\x83\xf1\x92_\x88\xf3\x91]\xbb\xc5\x9e@\x90\xff\xaeU\x80\xf6\x82')

    def test_challenge(self):
        resp = LafCrypto.encrypt_kilo_challenge(self.key, unhexlify(b'f29ae130'))
        self.assertEqual(resp, unhexlify(b'2f47ca81ebeee6f414263c0542c8d132'))
