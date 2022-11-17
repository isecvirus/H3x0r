import hashlib


def Shake256(string: bytes, type: str, length: int):
    if type == 'hexdigest':
        return hashlib.shake_256(string).hexdigest(length)
    elif type == 'digest':
        return str(hashlib.shake_256(string).digest(length))[2:-1]
