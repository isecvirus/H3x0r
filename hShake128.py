import hashlib


def Shake128(string: bytes, type: str, length: int):
    if type == 'hexdigest':
        return hashlib.shake_128(string).hexdigest(length)
    elif type == 'digest':
        return str(hashlib.shake_128(string).digest(length))[2:-1]
