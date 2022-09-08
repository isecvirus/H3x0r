import base64


def Encode_base64(string):
    try:
        return base64.b64encode(string.encode())
    except Exception:
        return ''

def Decode_base64(string):
    try:
        return base64.b64decode(string)
    except Exception:
        return ''
