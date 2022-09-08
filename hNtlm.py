import binascii
import hashlib


def Ntlm(string:str):
    hash = hashlib.new('md4', string.encode('utf-16le')).digest()
    return str(binascii.hexlify(hash))[2:-1]