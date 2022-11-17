import hashlib


def Sha256(string: bytes, type: str):
    if type == 'hexdigest':
        return hashlib.sha256(string).hexdigest()
    elif type == 'digest':
        return str(hashlib.sha256(string).digest())[2:-1]
