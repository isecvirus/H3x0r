Morse_codes = {
    "": "",
    "A": "._",
    "Á": ".__._",
    "Ä": "._._",
    "B": "_...",
    "C": "_._.",
    "D": "_..",
    "E": ".",
    "É": ".._..",
    "F": ".._",
    "G": "__.",
    "H": "....",
    "I": "..",
    "J": ".___",
    "K": "_._",
    "L": "._..",
    "M": "__",
    "N": "_.",
    "Ñ": "__.__",
    "O": "___",
    "Ö": "___.",
    "P": ".__.",
    "Q": "__._",
    "R": "._.",
    "S": "...",
    "T": "_",
    "U": ".._",
    "Ü": "..__",
    "V": "..._",
    "W": ".__",
    "X": "_.._",
    "Y": "_.__",
    "Z": "__..",
    "0": "_____",
    "1": ".____",
    "2": "..___",
    "3": "...__",
    "4": "...._",
    "5": ".....",
    "6": "_....",
    "7": "__...",
    "8": "___..",
    "9": "____.",
    "!": "_._.__",
    '"': "._.._.",
    "&": "._...",
    "'": ".____.",
    "(": "_.__.",
    ")": "_.__._",
    "+": "._._.",
    ",": "__..__",
    "-": "_...._",
    ".": "._._._",
    "/": "_._._.",
    ":": "___...",
    ";": "_._._.",
    "=": "_..._",
    "?": "..__..",
    "@": ".__._.",
    "$": "$"
}

"""
Test-> #1 @1 $10000000, dude that's great I like it... Loading !@#$%^&*()_+}{|":?><~!`
_ . ... _ _...._    .____  .__._. .____  $ .____ _____ _____ _____ _____ _____ _____ _____ __.__  _.. .._ _.. .  _ .... ._ _ .____. ...  __. ._. . ._ _  ..  ._.. .. _._ .  .. _ ._._._ ._._._ ._._._  ._.. ___ ._ _.. .. _. __.  _._.__ .__._.  $   ._...  _.__. _.__._  ._._.    ._.._. ___... ..__..    _._.__
"""
def Morse_encrypt(text):
    cipher = ''
    for letter in text.upper():
        if letter != ' ':
            try:
                cipher += ' ' + Morse_codes[letter] + ' '
            except:
                cipher += letter
        else:
            cipher += ' '
    return cipher
def Morse_decrypt(morse):
    text = ''
    for Cipher in morse.split(' '):
        if Cipher != ' ':
            try:
                text += list(Morse_codes.keys())[list(Morse_codes.values()).index(Cipher)]
            except:
                text += Cipher
        else:
            text += ' '
    return text