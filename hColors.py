import re

import matplotlib.colors
from colour import Color

def Hex2Color(hex:str):
    try:
        if "#" not in str(Color(hex)):
            return Color(hex)
        else:
            return ''
    except Exception:
        return ''
def Hex2RGB(hex:str):
    try:
        # rgb(*.*, *.*, *.*)
        converter = matplotlib.colors.colorConverter.to_rgb
        r,g,b = converter(hex)
        result = f"rgb({int(r*255)}, {int(g*255)}, {int(b*255)})"
        return result

    except Exception:
        return ''
def Color2RGB(color:str):
    try:
        return Hex2RGB(Color2Hex(color))
    except Exception:
        return ''
def Color2Hex(color:str):
    try:
        converter = matplotlib.colors.colorConverter.colors
        color = converter.get(color)

        if color:
            return str(color).lower()
        else:
            return ''
    except Exception:
        return ''
def RGB2Hex(rgb:str):
    try:
        reg_rgb = re.findall("(\d+)", rgb)
        (r, g, b) = (
            int(reg_rgb[0]), # red   : <0, >255
            int(reg_rgb[1]), # green : <0, >255
            int(reg_rgb[2])  # blue  : <0, >255
        )

        if (r >= 0 and r <= 255) and (g >= 0 and g <= 255) and (b >= 0 and b <= 255):
            red = "%02x" % r
            green = "%02x" % g
            blue = "%02x" % b
            return "#%s" % (red + green + blue)
        else:
            return ''
    except Exception:
        return ''
def RGB2Color(rgb:str):
    try:
        return Hex2Color(RGB2Hex(rgb=rgb))
    except Exception:
        return ''