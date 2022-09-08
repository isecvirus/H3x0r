import zlib


def _Crc32_(string:bytes):
    """
    :param string: Any
    :return: Crc-32 hash
    """
    return zlib.crc32(string)