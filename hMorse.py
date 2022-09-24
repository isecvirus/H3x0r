import re
import string

pre_morse = {
    "": "",
    "A": "•—",
    # "Á": "•__•_",
    # "Ä": "•_•_",
    "B": "—•••",
    "C": "—•—•",
    "D": "—••",
    "E": "•",
    # "É": "••_••",
    "F": "••—•",
    "G": "——•",
    "H": "••••",
    "I": "••",
    "J": "•———",
    "K": "—•—",
    "L": "•—••",
    "M": "——",
    "N": "—•",
    # "Ñ": "__•__",
    "O": "———",
    # "Ö": "___•",
    "P": "•——•",
    "Q": "——•—",
    "R": "•—•",
    "S": "•••",
    "T": "—",
    "U": "••—",
    # "Ü": "••__",
    "V": "•••—",
    "W": "•——",
    "X": "—••—",
    "Y": "—•——",
    "Z": "——••",
    "0": "—————",
    "1": "•————",
    "2": "••———",
    "3": "•••——",
    "4": "••••—",
    "5": "•••••",
    "6": "—••••",
    "7": "——•••",
    "8": "———••",
    "9": "————•",
    "!": "—•—•——",
    '"': "•—••—•",
    "&": "•—•••",
    "'": "•————•",
    "(": "—•——•",
    ")": "—•——•—",
    "+": "•—•—•",
    ",": "——••——",
    "-": "—••••—",
    ".": "•—•—•—",
    "/": "—••—•",
    ":": "———•••",
    ";": "—•—•—•",
    "=": "—•••—",
    "?": "••——••",
    "@": "•——•—•"
}

def Morse_codes(dash:str, dot:str) -> dict:
    morse = {}
    for pm in pre_morse:
        morse[pm] = pre_morse[pm].replace("—", dash).replace("•", dot)
    return morse

def Morse_encode(text:str, seperator:str="/", space:str=" ", dash:str="•", dot:str="—"):
    """
    :param text: normal string to encode.
    :param seperator: the (every) character seperator (deep).
    :param space: the (every) word seperator (wordy).
    :param dash: (what is) the default morse characters dash.
    :param dot: (what is) the default morse characters dot.
    :return: encoded string as much as possible.
    """

    mc = Morse_codes(dash=dash, dot=dot)
    cipher = []
    reg_string = re.sub("\s", repl=space, string=text)

    for char in reg_string:
        for c in char.upper():
            try: # try to add -----------------*
                cipher.append(mc[c]) # the morse code from the character
            except: # handle the exception if it's not there
                cipher.append(c) # add the character as it is.
    return seperator.join(cipher) # then return the encoded string

def Morse_decode(morse, seperator, space, dash, dot):
    """
    :param morse: the full encoded string.
    :param seperator: the (every) morse character seperator (deep).
    :param space: the (every) morse word seperator (wordy).
    :param dash: (what is) the default morse characters dash.
    :param dot: (what is) the default morse characters dot.
    :return: decoded string as much as possible.
    """

    mc = Morse_codes(dash=dash, dot=dot)
    text = []

    for spa in morse.split(space): # spa=space
        for sep in spa.split(seperator): # m=morse
            if sep != '':
                try:
                    text.append(list(mc.keys())[list(mc.values()).index(sep)])
                except:
                    text.append(sep)
            else:
                text += ' '
    return re.sub("\s+", string=''.join(text), repl=space).lower()