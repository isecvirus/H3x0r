import base64


def Encode_base32(string):
    try:
        return base64.b32encode(string.encode())
    except Exception:
        return ''

def Decode_base32(string):
    try:
        return base64.b32decode(string)
    except Exception:
        return ''
