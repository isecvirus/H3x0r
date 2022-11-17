import base64


def Encode_base64_urlsafe(string):
    try:
        return base64.urlsafe_b64encode(string.encode())
    except Exception:
        return ''

def Decode_base64_urlsafe(string):
    try:
        return base64.urlsafe_b64decode(string)
    except Exception:
        return ''
