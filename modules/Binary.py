# Hello, world.
# 01001000 01100101 01101100 01101100 01101111 00101100 00100000 01110111 01101111 01110010 01101100 01100100 00101110

import re
Binary_dict = {
    'a': '01100001', # English alphabet (Lower case)
    'b': '01100010', # English alphabet (Lower case)
    'c': '01100011', # English alphabet (Lower case)
    'd': '01100100', # English alphabet (Lower case)
    'e': '01100101', # English alphabet (Lower case)
    'f': '01100110', # English alphabet (Lower case)
    'g': '01100111', # English alphabet (Lower case)
    'h': '01101000', # English alphabet (Lower case)
    'i': '01101001', # English alphabet (Lower case)
    'j': '01101010', # English alphabet (Lower case)
    'k': '01101011', # English alphabet (Lower case)
    'l': '01101100', # English alphabet (Lower case)
    'm': '01101101', # English alphabet (Lower case)
    'n': '01101110', # English alphabet (Lower case)
    'o': '01101111', # English alphabet (Lower case)
    'p': '01110000', # English alphabet (Lower case)
    'q': '01110001', # English alphabet (Lower case)
    'r': '01110010', # English alphabet (Lower case)
    's': '01110011', # English alphabet (Lower case)
    't': '01110100', # English alphabet (Lower case)
    'u': '01110101', # English alphabet (Lower case)
    'v': '01110110', # English alphabet (Lower case)
    'w': '01110111', # English alphabet (Lower case)
    'x': '01111000', # English alphabet (Lower case)
    'y': '01111001', # English alphabet (Lower case)
    'z': '01111010', # English alphabet (Lower case)

    'A': '01000001', # English alphabet (Upper case)
    'B': '01000010', # English alphabet (Upper case)
    'C': '01000011', # English alphabet (Upper case)
    'D': '01000100', # English alphabet (Upper case)
    'E': '01000101', # English alphabet (Upper case)
    'F': '01000110', # English alphabet (Upper case)
    'G': '01000111', # English alphabet (Upper case)
    'H': '01001000', # English alphabet (Upper case)
    'I': '01001001', # English alphabet (Upper case)
    'J': '01001010', # English alphabet (Upper case)
    'K': '01001011', # English alphabet (Upper case)
    'L': '01001100', # English alphabet (Upper case)
    'M': '01001101', # English alphabet (Upper case)
    'N': '01001110', # English alphabet (Upper case)
    'O': '01001111', # English alphabet (Upper case)
    'P': '01010000', # English alphabet (Upper case)
    'Q': '01010001', # English alphabet (Upper case)
    'R': '01010010', # English alphabet (Upper case)
    'S': '01010011', # English alphabet (Upper case)
    'T': '01010100', # English alphabet (Upper case)
    'U': '01010101', # English alphabet (Upper case)
    'V': '01010110', # English alphabet (Upper case)
    'W': '01010111', # English alphabet (Upper case)
    'X': '01011000', # English alphabet (Upper case)
    'Y': '01011001', # English alphabet (Upper case)
    'Z': '01011010', # English alphabet (Upper case)

    '0': '00110000', # English numbers
    '1': '00110001', # English numbers
    '2': '00110010', # English numbers
    '3': '00110011', # English numbers
    '4': '00110100', # English numbers
    '5': '00110101', # English numbers
    '6': '00110110', # English numbers
    '7': '00110111', # English numbers
    '8': '00111000', # English numbers
    '9': '00111001', # English numbers

    '٠': '00110000', # Arabic numbers
    '١': '00110001', # Arabic numbers
    '٢': '00110010', # Arabic numbers
    '٣': '00110011', # Arabic numbers
    '٤': '00110100', # Arabic numbers
    '٥': '00110101', # Arabic numbers
    '٦': '00110110', # Arabic numbers
    '٧': '00110111', # Arabic numbers
    '٨': '00111000', # Arabic numbers
    '٩': '00111001', # Arabic numbers

    'ا': '11011000', # Arabic alphabet
    'أ': '10100111', # Arabic alphabet
    'ب': '00001010', # Arabic alphabet
    'ت': '11011000', # Arabic alphabet
    'ث': '10100011', # Arabic alphabet
    'ح': '00001010', # Arabic alphabet
    'خ': '11011000', # Arabic alphabet
    'د': '10101000', # Arabic alphabet
    'ذ': '00001010', # Arabic alphabet
    'ر': '11011000', # Arabic alphabet
    'ز': '10101010', # Arabic alphabet
    'س': '00001010', # Arabic alphabet
    'ش': '11011000', # Arabic alphabet
    'ص': '10101011', # Arabic alphabet
    'ض': '00001010', # Arabic alphabet
    'ط': '11011000', # Arabic alphabet
    'ظ': '10101101', # Arabic alphabet
    'ع': '00001010', # Arabic alphabet
    'غ': '11011000', # Arabic alphabet
    'ف': '10101110', # Arabic alphabet
    'ق': '00001010', # Arabic alphabet
    'ك': '11011000', # Arabic alphabet
    'ل': '10101111', # Arabic alphabet
    'م': '00001010', # Arabic alphabet
    'ن': '11011000', # Arabic alphabet
    'ه': '10110000', # Arabic alphabet
    'و': '00001010', # Arabic alphabet
    'ي': '11011000', # Arabic alphabet

    '!': '00100001', # Punctuation
    '"': '00100010', # Punctuation
    '#': '00100011', # Punctuation
    '$': '00100100', # Punctuation
    '%': '00100101', # Punctuation
    '&': '00100110', # Punctuation
    "'": '00100111', # Punctuation
    '(': '00101000', # Punctuation
    ')': '00101001', # Punctuation
    '*': '00101010', # Punctuation
    '+': '00101011', # Punctuation
    ',': '00101100', # Punctuation
    '-': '00101101', # Punctuation
    '.': '00101110', # Punctuation
    '/': '00101111', # Punctuation
    ':': '00111010', # Punctuation
    ';': '00111011', # Punctuation
    '<': '00111100', # Punctuation
    '=': '00111101', # Punctuation
    '>': '00111110', # Punctuation
    '?': '00111111', # Punctuation
    '@': '01000000', # Punctuation
    '[': '01011011', # Punctuation
    '\\':'01011100', # Punctuation
    ']': '01011101', # Punctuation
    '^': '01011110', # Punctuation
    '_': '01011111', # Punctuation
    '`': '01100000', # Punctuation
    '{': '01111011', # Punctuation
    '|': '01111100', # Punctuation
    '}': '01111101', # Punctuation
    '~': '01111110', # Punctuation
    ' ': '00100000'  # Punctuation
}

def Binary_encrypt(text: str, separator: str):
    Binary = ''

    for t in text:
        if t in list(Binary_dict.keys()):
            Binary += list(Binary_dict.values())[list(Binary_dict.keys()).index(t)] + separator
    try:
        if Binary[-1] == separator:
            return Binary[:-1]
        else:
            return Binary
    except IndexError:
        return ''
def Binary_decrypt(binary: str, separator: str):
    Text = ''

    if separator != '':
        for b in str(binary).split(separator):
            if b in list(Binary_dict.values()):
                Text += list(Binary_dict.keys())[list(Binary_dict.values()).index(b)]
        return Text

    elif separator == '':
        None_Separator_Binary = re.findall('........', binary)
        for b in None_Separator_Binary:
            if b in list(Binary_dict.values()):
                Text += list(Binary_dict.keys())[list(Binary_dict.values()).index(b)]
        return Text
def Binary_identify(binary: str):
    for b in list(Binary_dict.values()):
        if b in binary:
            return True
        else:
            return False
