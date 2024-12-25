from easycrypt import AES

from easycrypt.encrypt.algo import CryptoAlgo
from tests.t_crypt.cryptotest import TestCryptoAlgo


class TestAESCryptography(TestCryptoAlgo):

    def get_algorithm(self) -> CryptoAlgo:
        return AES()


if __name__ == '__main__':
    TestAESCryptography.execute_all()
