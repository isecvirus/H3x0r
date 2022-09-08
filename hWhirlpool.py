import whirlpool


def Whirlpool(string:str, type:str):
    """
    :param string: Any
    :return: Whirlpool hash
    """
    if type == "hexdigest":
        hash = whirlpool.new()
        hash.update(string.encode())
        return hash.hexdigest()
    elif type == "digest":
        hash = whirlpool.new()
        hash.update(string.encode())
        return str(hash.digest())[2:-1]