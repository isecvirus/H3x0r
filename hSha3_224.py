import hashlib


def Sha3_224(string: bytes, type: str):
    if type == 'hexdigest':
        return hashlib.sha3_224(string).hexdigest()
    elif type == 'digest':
        return str(hashlib.sha3_224(string).digest())[2:-1]
