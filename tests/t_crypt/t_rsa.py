from cryptoalgos.encrypt import RSA
from cryptoalgos.encrypt.algo import CryptoAlgo
from tests.t_crypt import cryptotest


# -------------------------------------------

class RSATest(cryptotest.TestCryptoAlgo):

    def get_algorithm(self) -> CryptoAlgo:
        return RSA()

    def setUp(self):
        self.private_key, self.public_key = RSA.get_key_pair()
        super().setUp()

    def test_strkey_roundtript(self):
        encrypted = self.algorithm.encrypt(content=self.test_content, key=self.encryption_key)
        decrypted = self.algorithm.decrypt(content=encrypted, key=self.decryption_key)
        self.assertEqual(decrypted, self.test_content)

    def get_encryption_key(self):
        return RSA.get_pem(self.public_key, is_private=False)

    def get_decryption_key(self):
        return RSA.get_pem(self.private_key, is_private=True)

    @staticmethod
    def showcase():
        rsa_crypto = RSA()
        private_key, public_key = RSA.get_key_pair()

        private_pem = RSA.get_pem(private_key, is_private=True)
        public_pem = RSA.get_pem(public_key, is_private=False)

        encrypted_message = rsa_crypto.encrypt(key=public_pem, content='Hello, RSA!')
        print('Encrypted:', encrypted_message)

        decrypted_message = rsa_crypto.decrypt(content=encrypted_message, key=private_pem)
        print('Decrypted:', decrypted_message)

if __name__ == "__main__":
    RSATest.execute_all()