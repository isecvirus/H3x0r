import hashlib


def Black2s(string: str, type: str):
    if type == 'hexdigest':
        return hashlib.blake2s(string.encode()).hexdigest()
    elif type == 'digest':
        return str(hashlib.blake2s(string.encode()).digest())[2:-1]
