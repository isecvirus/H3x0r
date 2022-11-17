import binascii


def Encode_Hexadecimal(data:str):
    try:
        return str(binascii.hexlify(data.encode()))[2:-1]
    except Exception:
        return ''

def Decode_Hexadecimal(data:str):
    try:
        return str(binascii.unhexlify(data.encode()))[2:-1]
    except Exception:
        return ''