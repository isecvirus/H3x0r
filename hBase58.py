import base58


def Encode_base58(string):
    try:
        return base58.b58encode(string.encode())
    except Exception:
        return ''

def Decode_base58(string):
    try:
        return base58.b58encode(string)
    except Exception:
        return ''
