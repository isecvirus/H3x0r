import base64


def Encode_base85(string):
    try:
        return base64.b85encode(string.encode())
    except Exception:
        return ''

def Decode_base85(string):
    try:
        return base64.b85decode(string)
    except Exception:
        return ''
