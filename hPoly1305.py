from Crypto.Cipher import AES
from Crypto.Hash import Poly1305


def _Poly1305_(key:str, string:str, type:str):
    """
    :param key: length must be 32
    :param string: Any
    :return: Poly1305 hash
    """
    if type == "hexdigest":
        hash = Poly1305.new(data=string.encode(), cipher=AES, key=key.encode())
        return hash.hexdigest()
    elif type == "digest":
        hash = Poly1305.new(data=string.encode(), cipher=AES, key=key.encode())
        return str(hash.digest())[2:-1]