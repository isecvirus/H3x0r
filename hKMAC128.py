from Crypto.Hash import KMAC128

def _KMAC128_(data:str, key:str, type:str):
    if type == "hexdigest":
        return KMAC128.new(data=data.encode(), key=key.encode()).hexdigest()
    elif type == "digest":
        return KMAC128.new(data=data.encode(), key=key.encode()).digest()