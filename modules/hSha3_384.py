import hashlib


def Sha3_384(string: bytes, type: str):
    if type == 'hexdigest':
        return hashlib.sha3_384(string).hexdigest()
    elif type == 'digest':
        return str(hashlib.sha3_384(string).digest())[2:-1]
