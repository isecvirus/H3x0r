def Rot13_encode(string):
    encrypted = ""
    # traverse text
    for ind in range(len(string)):
        char = string[ind]
        # Encrypt uppercase characters

        if char.isalpha():
            charis = 65 if char.isupper() else 97
            encrypted += chr((ord(char) + 13 - charis) % 26 + charis)
        # Encrypt lowercase characters
        else:
            encrypted += char
    return encrypted

def Rot13_decode(string):
    decrypted = ''
    for char in string:
        if char.isalpha():
            # find the position in 0-25
            char_unicode = ord(char)
            char_index = ord(char) - (ord("A") if char.isupper() else ord('a'))
            # perform the negative shift
            new_index = (char_index - 13) % 26
            # convert to new character
            new_unicode = new_index + (ord("A") if char.isupper() else ord('a'))
            new_character = chr(new_unicode)
            # append to plain string
            decrypted += new_character
        else:
            decrypted += char
    return decrypted
