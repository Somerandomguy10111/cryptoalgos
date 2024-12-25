import os
from abc import abstractmethod

from easycrypt import AES
from holytools.devtools import Unittest

from easycrypt.encrypt.algo import CryptoAlgo


class TestCryptoAlgo(Unittest):
    def setUp(self):
        self.algorithm = self.get_algorithm()
        self.test_content = "Hello, World!"
        self.test_key_str = "password123"
        self.test_key_bytes = os.urandom(32)
        self.test_content_empty = ""
        self.test_content_special = "特殊字符123"

    def test_successful_encryption_decryption_str_key(self):
        encrypted = self.algorithm.encrypt(key=self.test_content, self.test_key_str)
        decrypted = self.algorithm.decrypt(self.test_key_str, encrypted)
        self.assertEqual(decrypted, self.test_content)

    def test_successful_encryption_decryption_byte_key(self):
        encrypted = self.algorithm.encrypt(self.test_content, self.test_key_bytes)
        decrypted = self.algorithm.decrypt(encrypted, self.test_key_bytes)
        self.assertEqual(decrypted, self.test_content)

    def test_encryption_decryption_different_keys(self):
        encrypted = self.algorithm.encrypt(self.test_content, self.test_key_str)
        decrypted = self.algorithm.decrypt("wrong_key", encrypted)
        self.assertNotEqual(decrypted, self.test_content)

    def test_handle_empty_string(self):
        encrypted = self.algorithm.encrypt(self.test_content_empty, self.test_key_str)
        decrypted = self.algorithm.decrypt(self.test_key_str, encrypted)
        self.assertEqual(decrypted, self.test_content_empty)

    def test_handle_special_characters(self):
        encrypted = self.algorithm.encrypt(self.test_content_special, self.test_key_str)
        decrypted = self.algorithm.decrypt(self.test_key_str, encrypted)
        self.assertEqual(decrypted, self.test_content_special)

    def test_decryption_altered_data(self):
        encrypted = self.algorithm.encrypt(self.test_content, self.test_key_str)
        altered_encrypted = encrypted[:-1] + chr((ord(encrypted[-1]) + 1) % 256)
        decrypted = self.algorithm.decrypt(self.test_key_str, altered_encrypted)
        self.assertNotEqual(decrypted, self.test_content)

    def test_very_long_string(self):
        long_content = "A" * 10000
        encrypted = self.algorithm.encrypt(long_content, self.test_key_str)
        decrypted = self.algorithm.decrypt(self.test_key_str, encrypted)
        self.assertEqual(decrypted, long_content)

    @abstractmethod
    def get_algorithm(self) -> CryptoAlgo:
        pass

# Running the tests
if __name__ == '__main__':
    TestCryptoAlgo.execute_all()
