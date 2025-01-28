from abc import abstractmethod
from typing import Optional, Union


class CryptoAlgo:
    @abstractmethod
    def encrypt(self, content: str, key: Union[str, bytes]) -> str:
        pass

    @abstractmethod
    def decrypt(self, content: str, key: Union[str, bytes]) -> Optional[str]:
        pass