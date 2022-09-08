import crc16


def _Crc16_(string:bytes):
    """
    :param string: Any
    :return: Crc-16 hash
    """
    return crc16.crc16xmodem(string)