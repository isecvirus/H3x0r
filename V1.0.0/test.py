from cryptography.fernet import Fernet

def Fernet_encryption(msg:str):
    key = Fernet.generate_key()
    print(key)
    f = Fernet(key)
    output = f.encrypt(msg.encode())
    print(output)

    print(f.decrypt(output))

    return "data: %s\nkey : %s" % (str(output)[2:-1], str(key)[2:-1])

print(Fernet_encryption("A really secret message. Not for prying eyes."))