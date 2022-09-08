import base64

def Encode_base16(string):
    try:
        return base64.b16encode(string.encode())
    except Exception:
        return ''
def Decode_base16(string):
    try:
        return base64.b16decode(string)
    except Exception:
        return ''
