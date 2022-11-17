import hashlib


def Ripemd_160(string:bytes, type:str):
    if type == "hexdigest":
        return hashlib.new('ripemd160', string).hexdigest()
    elif type == "digest":
        return str(hashlib.new('ripemd160', string).digest())[2:-1]