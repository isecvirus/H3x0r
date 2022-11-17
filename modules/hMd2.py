from Crypto.Hash import MD2


def _Md2_(string:bytes, type:str):
    if type == "hexdigest":
        return MD2.new(string).hexdigest()
    elif type == "digest":
        return str(MD2.new(string).digest())[2:-1]