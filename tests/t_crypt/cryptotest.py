import os
import unittest
from abc import abstractmethod

from holytools.devtools import Unittest

from easycrypt import RSA
from easycrypt.encrypt.algo import CryptoAlgo


class TestCryptoAlgo(Unittest):
    def setUp(self):
        self.algorithm = self.get_algorithm()
        self.test_content = "Hello, World!"
        self.encryption_key = self.get_encryption_key()
        self.decryption_key = self.get_decryption_key()
        self.test_key_bytes = os.urandom(32)
        self.test_content_empty = ""
        self.test_content_special = "特殊字符123"

    def test_strkey_roundtript(self):
        encrypted = self.algorithm.encrypt(content=self.test_content, key=self.encryption_key)
        decrypted = self.algorithm.decrypt(key=self.decryption_key, content=encrypted)
        self.assertEqual(decrypted, self.test_content)

    def test_emptystring_roundtrip(self):
        encrypted = self.algorithm.encrypt(content=self.test_content_empty, key=self.encryption_key)
        decrypted = self.algorithm.decrypt(key=self.decryption_key, content=encrypted)
        self.assertEqual(decrypted, self.test_content_empty)

    def test_specialchar_roundtrip(self):
        encrypted = self.algorithm.encrypt(content=self.test_content_special, key=self.encryption_key)
        decrypted = self.algorithm.decrypt(key=self.decryption_key, content=encrypted)
        self.assertEqual(decrypted, self.test_content_special)

    def test_longstring_roundtrip(self):
        if isinstance(self.algorithm, RSA):
            self.skipTest("RSA is not suitable for long strings")

        long_content = "A" * 10000
        encrypted = self.algorithm.encrypt(content=long_content, key=self.encryption_key)
        decrypted = self.algorithm.decrypt(key=self.decryption_key, content=encrypted)
        self.assertEqual(decrypted, long_content)

    # -----------------
    # non-matching data

    def test_different_keys_roundtrip(self):
        encrypted = self.algorithm.encrypt(content=self.test_content, key=self.encryption_key)
        with self.assertRaises(Exception):
            decrypted = self.algorithm.decrypt(key="wrong_key", content=encrypted)
            if decrypted != self.test_content:
                raise Exception(f'Encrypted and decrypted content do not match')

    def test_decryption_altered_data(self):
        encrypted = self.algorithm.encrypt(content=self.test_content, key=self.encryption_key)
        altered_encrypted = encrypted[:-4] + chr((ord(encrypted[-1]) + 1) % 256) + '=='

        with self.assertRaises(Exception):
            decrypted = self.algorithm.decrypt(key=self.encryption_key, content=altered_encrypted)
            if decrypted != self.test_content:
                raise Exception(f'Encrypted and decrypted content do not match')


    @abstractmethod
    def get_algorithm(self) -> CryptoAlgo:
        pass

    @abstractmethod
    def get_encryption_key(self):
        pass

    @abstractmethod
    def get_decryption_key(self):
        pass

# Running the tests
if __name__ == '__main__':
    unittest.main()