import os
from base64 import b64encode, b64decode
from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, CipherContext

from cryptoalgos.hash import SHA
from .algo import CryptoAlgo


# -------------------------------------------


class AES(CryptoAlgo):
    def __init__(self):
        self.backend = default_backend()
        self.sha = SHA()


    def encrypt(self, content: str, key : Union[str, bytes]) -> str:
        iv = os.urandom(16)
        byte_content = content.encode()

        encryptor = self._get_encryptor(byte_key=self.get_byte_key(key=key), iv=iv)
        encrypted_content = encryptor.update(byte_content) + encryptor.finalize()

        return b64encode(iv + encrypted_content).decode()

    def decrypt(self, content: str, key : Union[str, bytes]) -> str:
        encrypted_data = b64decode(content)
        iv, data  = encrypted_data[:16], encrypted_data[16:]

        decryptor = self._get_decryptor(byte_key=self.get_byte_key(key=key), iv=iv)
        decrypted_content = decryptor.update(data) + decryptor.finalize()
        try:
            decoded = decrypted_content.decode()
        except UnicodeDecodeError:
            raise ValueError(f'Error decoding bytes to UTF-8. Most likely the decryption key is not correct')

        return decoded

    # -------------------------------------------
    # get

    def get_byte_key(self, key : Union[str, bytes]):
        byte_key = self.sha.get_hash(txt=key) if isinstance(key, str) else key
        if not len(byte_key) == 32:
            raise IOError(f'Key must be 32 bytes long, but got {len(byte_key)} bytes.')
        return byte_key

    def _get_encryptor(self, byte_key : bytes, iv : bytes) -> CipherContext:
        return self._get_cipher(key=byte_key, iv=iv).encryptor()

    def _get_decryptor(self, byte_key : bytes, iv : bytes) -> CipherContext:
        return self._get_cipher(key=byte_key, iv=iv).decryptor()

    def _get_cipher(self, key : bytes, iv : bytes):
        return Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend)

