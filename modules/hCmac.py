from Crypto.Cipher import AES
from Crypto.Hash import CMAC


def Cmac(key:bytes, string:bytes, type:str):
    """
    :param key: length must be 16
    :param string: Any
    :return: Cmac hash
    """
    if type == "digest":
        hash = CMAC.new(key, ciphermod=AES)
        hash.update(string)
        return str(hash.digest())[2:-1]
    elif type == "hexdigest":
        hash = CMAC.new(key, ciphermod=AES)
        hash.update(string)
        return hash.hexdigest()