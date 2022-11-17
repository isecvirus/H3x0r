import bcrypt


def Bcrypt_Encryption(string:str):
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(string.encode(), salt)

    return f"salt: {str(salt)[2:-1]}\n" \
           f"hash: {str(hash)[2:-1]}"
def Bcrypt_Decryption(password:str, hashed_password:str):
    try:
        return bcrypt.checkpw(password=password.encode(), hashed_password=hashed_password.encode())
    except ValueError as error:
        return error