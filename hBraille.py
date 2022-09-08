brailles_codes = {
    ' ': '⠀',
    '!': '⠮',
    '"': '⠐',
    '#': '⠼',
    '$': '⠫',
    '%': '⠩',
    '&': '⠯',
    '': '⠄',
    '(': '⠷',
    ')': '⠾',
    '*': '⠡',
    '+': '⠬',
    ',': '⠠',
    '-': '⠤',
    '.': '⠨',
    '/': '⠌',
    '0': '⠴',
    '1': '⠂',
    '2': '⠆',
    '3': '⠒',
    '4': '⠲',
    '5': '⠢',
    '6': '⠖',
    '7': '⠶',
    '8': '⠦',
    '9': '⠔',
    ':': '⠱',
    ';': '⠰',
    '<': '⠣',
    '=': '⠿',
    '>': '⠜',
    '?': '⠹',
    '@': '⠈',
    'A': '⠁',
    'B': '⠃',
    'C': '⠉',
    'D': '⠙',
    'E': '⠑',
    'F': '⠋',
    'G': '⠛',
    'H': '⠓',
    'I': '⠊',
    'J': '⠚',
    'K': '⠅',
    'L': '⠇',
    'M': '⠍',
    'N': '⠝',
    'O': '⠕',
    'P': '⠏',
    'Q': '⠟',
    'R': '⠗',
    'S': '⠎',
    'T': '⠞',
    'U': '⠥',
    'V': '⠧',
    'W': '⠺',
    'X': '⠭',
    'Y': '⠽',
    'Z': '⠵',
    '[': '⠪',
    '\\': '⠳',
    ']': '⠻',
    '^': '⠘',
    '_': '⠸'
}

class BRAILLE:
    def encode(self, text):
        output = ""
        for t in text:
            if str(t).upper() in brailles_codes:
                output += brailles_codes[str(t).upper()]
            else:
                output += t
        return output

    def decode(self, braille):
        output = ""
        for b in braille:
            if b in brailles_codes.values():
                output += list(brailles_codes.keys())[list(brailles_codes.values()).index(b)]
            else:
                output += b
        return output
Braille = BRAILLE()
