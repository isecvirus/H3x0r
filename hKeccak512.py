from Crypto.Hash import keccak


def Keccak512(string:bytes, type:str):
    if type == "hexdigest":
        hash = keccak.new(digest_bits=512)
        hash.update(string)
        return hash.hexdigest()
    elif type == "digest":
        hash = keccak.new(digest_bits=512)
        hash.update(string)
        return str(hash.digest())[2:-1]