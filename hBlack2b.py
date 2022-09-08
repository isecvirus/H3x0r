import hashlib


def Black2b(string: str, type: str):
    if type == 'hexdigest':
        return hashlib.blake2b(string.encode()).hexdigest()
    elif type == 'digest':
        return str(hashlib.blake2b(string.encode()).digest())[2:-1]
