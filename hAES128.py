import cryptography.fernet
from cryptography.fernet import Fernet

"""
Fernet uses 128-bit AES in CBC mode and PKCS7 padding, with HMAC using SHA256 for authentication.
"""

def AES128_Encryption(data: str):
    key = Fernet.generate_key()
    obj = Fernet(key)
    encrypted = obj.encrypt(data.encode())

    return \
        f"Key: {str(key)[2:-1]}\n" \
        f"{str(encrypted)[2:-1]}"
def AES128_Decryption(data: str, key: str):
    try:
        obj = Fernet(key.encode())
        decrypted = obj.decrypt(data.encode())
        return str(decrypted)[2:-1]
    except cryptography.fernet.InvalidToken:
        return "Invalid key (:"
    except ValueError:
        return "Key must be 32 url-safe base64 encoding"