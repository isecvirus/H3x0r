import hashlib

def Md5(string: bytes, type: str):
    if type == 'hexdigest':
        return hashlib.md5(string).hexdigest()
    elif type == 'digest':
        return str(hashlib.md5(string).digest())[2:-1]
