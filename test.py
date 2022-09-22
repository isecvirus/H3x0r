import zlib

import matplotlib.colors
from colour import Color
from colorsys import hls_to_rgb, hsv_to_rgb, rgb_to_hsv, rgb_to_hls, rgb_to_yiq, yiq_to_rgb
# from zlib import compressobj, decompressobj

# def Zlib_compress(data:str, level:int):
#     """
#     :param data: Any string (in bytes)
#     :param level: -1 > 9
#     :return:
#     """
#     zobj = compressobj(level=level, wbits=zlib.MAX_WBITS)
#     return zobj.compress(data.encode())
#
# def Zlib_decompress(data:str):
#     """
#     :param data: Any string (in bytes)
#     :param level: -1 > 9
#     :return:
#     """
#     zobj = decompressobj(zlib.MAX_WBITS)
#     return zobj.decompress(data.encode())

def Hex2Color(hex:str):
    try:
        return Color(hex)
    except Exception:
        return ''
def Hex2RGB(hex:str):
    try:
        converter = matplotlib.colors.colorConverter.to_rgb
        return converter(hex)
    except Exception:
        return ''
def Color2Hex(color:str):
    converter = matplotlib.colors.colorConverter.colors
    converter.keys()
    color = converter.get(color)
    if color:
        return str(color).lower()
    else:
        return ''