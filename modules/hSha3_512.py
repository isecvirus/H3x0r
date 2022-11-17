import hashlib


def Sha3_512(string: bytes, type: str):
    if type == 'hexdigest':
        return hashlib.sha3_512(string).hexdigest()
    elif type == 'digest':
        return str(hashlib.sha3_512(string).digest())[2:-1]
