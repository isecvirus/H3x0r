from Crypto.Hash import KMAC256

def _KMAC256_(data:str, key:str, type:str):
    if type == "hexdigest":
        return KMAC256.new(data=data.encode(), key=key.encode()).hexdigest()
    elif type == "digest":
        return KMAC256.new(data=data.encode(), key=key.encode()).digest()