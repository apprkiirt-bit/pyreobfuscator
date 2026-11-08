import hashlib
import os
import sys
import unittest

from pyreobfuscator import crypto


class CryptoTest(unittest.TestCase):
    def test_rfc8439_vector(self):
        key = bytes.fromhex(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        )
        nonce = bytes.fromhex("070000004041424344454647")
        aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
        plaintext = (
            b"Ladies and Gentlemen of the class of '99: If I could offer you only "
            b"one tip for the future, sunscreen would be it."
        )
        expected_ciphertext = bytes.fromhex(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b6116"
        )
        expected_tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
        blob = crypto.seal(key, plaintext, nonce=nonce, aad=aad)
        self.assertEqual(blob[12:-16], expected_ciphertext)
        self.assertEqual(blob[-16:], expected_tag)
        self.assertEqual(crypto.open_sealed(key, blob, aad=aad), plaintext)

    def test_seal_roundtrip(self):
        key = os.urandom(32)
        for size in (0, 1, 15, 16, 17, 63, 64, 65, 1000):
            payload = os.urandom(size)
            blob = crypto.seal(key, payload)
            self.assertEqual(crypto.open_sealed(key, blob), payload)

    def test_tamper(self):
        key = os.urandom(32)
        blob = bytearray(crypto.seal(key, b"payload"))
        blob[-1] ^= 1
        with self.assertRaises(ValueError):
            crypto.open_sealed(key, bytes(blob))

    def test_aad_is_bound(self):
        key = os.urandom(32)
        blob = crypto.seal(key, b"payload", aad=b"module|code")
        self.assertEqual(crypto.open_sealed(key, blob, aad=b"module|code"), b"payload")
        with self.assertRaises(ValueError):
            crypto.open_sealed(key, blob, aad=b"other|code")

    def test_kdf_is_stable(self):
        key = b"k" * 32
        self.assertEqual(crypto.kdf(key, "x"), crypto.kdf(key, "x"))
        self.assertEqual(len(crypto.kdf(key, "x")), 32)
        self.assertNotEqual(crypto.kdf(key, "x"), crypto.kdf(key, "y"))


if __name__ == "__main__":
    unittest.main()
