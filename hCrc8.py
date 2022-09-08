import crc8


def _Crc8_(string:bytes, type:str):
    """
    :param string: Any
    :return: Crc-8 hash
    """
    if type == "hexdigest":
        hash = crc8.crc8()
        hash.update(string)
        return hash.hexdigest()
    elif type == "digest":
        hash = crc8.crc8()
        hash.update(string)
        return str(hash.digest())[2:-1]