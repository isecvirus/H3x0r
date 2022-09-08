import hashlib


def Sha384(string: bytes, type: str):
    if type == 'hexdigest':
        return hashlib.sha384(string).hexdigest()
    elif type == 'digest':
        return str(hashlib.sha384(string).digest())[2:-1]
