import hashlib


def Sha512(string: bytes, type: str):
    if type == 'hexdigest':
        return hashlib.sha512(string).hexdigest()
    elif type == 'digest':
        return str(hashlib.sha512(string).digest())[2:-1]
