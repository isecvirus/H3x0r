alphapet = [
    'a', 'k', 'u', 'E', 'O', 'Y', '8', '٨', 'ذ', 'غ', 'ي', '*', '>', '|',
    'b', 'l', 'v', 'F', 'P', 'Z', '9', '٩', 'ر', 'ف', '!', '+', '?', '}',
    'c', 'm', 'w', 'G', 'Q', '0', '٠', 'ا', 'ز', 'ق', '"', ',', '@', '~'
    'd', 'n', 'x', 'H', 'R', '1', '١', 'أ', 'س', 'ك', '#', '-', '[',
    'e', 'o', 'y', 'I', 'S', '2', '٢', 'ب', 'ش', 'ل', '$', '.', '\\',
    'f', 'p', 'z', 'J', 'T', '3', '٣', 'ت', 'ص', 'م', '%', '/', ']',
    'g', 'q', 'A', 'K', 'U', '4', '٤', 'ث', 'ض', 'ن', '&', ':', '^',
    'h', 'r', 'B', 'L', 'V', '5', '٥', 'ح', 'ط', 'ه', "'", ';', '_',
    'i', 's', 'C', 'M', 'W', '6', '٦', 'خ', 'ظ', 'ة', '(', '<', '`',
    'j', 't', 'D', 'N', 'X', '7', '٧', 'د', 'ع', 'و', ')', '=', '{',
]

def Encode_dummy(string: str, seperator: str = '.'):
    encoded = []
    for letter in string:
        if letter in alphapet:
            encoded.append(str(alphapet.index(letter) + 1))
        else:
            encoded.append(letter)
    return seperator.join(encoded)
def Decode_dummy(string: str, seperator: str = '.'):
    decoded = ''
    for l in string.split(seperator):
        try:
            decoded += alphapet[int(l) - 1]
        except Exception:
            decoded += l
    return decoded
