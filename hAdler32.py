import zlib


def Adler_32(string:bytes):
    """
    :param string: Any
    :return: Adler32 hash
    """
    return zlib.adler32(string)