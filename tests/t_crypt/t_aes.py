from easycrypt import AES
from easycrypt.encrypt.algo import CryptoAlgo
from tests.t_crypt import cryptotest


class TestAESCryptography(cryptotest.TestCryptoAlgo):

    def get_algorithm(self) -> CryptoAlgo:
        return AES()

    def get_encryption_key(self) -> str:
        return "password123"

    def get_decryption_key(self):
        return "password123"

if __name__ == '__main__':
    TestAESCryptography.execute_all()