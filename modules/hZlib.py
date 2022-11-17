from zlib import compressobj, MAX_WBITS # decompressobj

def Zlib_compress(data:str, level:int):
    """
    :param data: Any string (in bytes)
    :param level: -1 > 9
    :return:
    """
    zobj = compressobj(level=level)
    return zobj.compress(data.encode())

# def Zlib_decompress(data:str):
#     """
#     :param data: Any string (in bytes)
#     :param level: -1 > 9
#     :return:
#     """
#     zobj = decompressobj(MAX_WBITS)
#     return zobj.decompress(data.encode())