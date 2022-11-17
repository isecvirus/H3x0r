import hashlib


def Sha3_256(string: bytes, type: str):
    if type == 'hexdigest':
        return hashlib.sha3_256(string).hexdigest()
    elif type == 'digest':
        return str(hashlib.sha3_256(string).digest())[2:-1]
