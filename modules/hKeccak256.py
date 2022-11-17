from Crypto.Hash import keccak


def Keccak256(string:bytes, type:str):
    if type == "hexdigest":
        hash = keccak.new(digest_bits=256)
        hash.update(string)
        return hash.hexdigest()
    elif type == "digest":
        hash = keccak.new(digest_bits=256)
        hash.update(string)
        return str(hash.digest())[2:-1]