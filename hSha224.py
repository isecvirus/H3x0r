import hashlib


def Sha224(string: bytes, type: str):
    if type == 'hexdigest':
        return hashlib.sha1(string).hexdigest()
    elif type == 'digest':
        return str(hashlib.sha1(string).digest())[2:-1]
