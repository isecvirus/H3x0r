from Crypto.Hash import MD4


def _Md4_(string:bytes, type:str):
    if type == "hexdigest":
        return MD4.new(string).hexdigest()
    elif type == "digest":
        return MD4.new(string).digest()