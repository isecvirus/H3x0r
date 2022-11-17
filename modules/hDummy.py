english_letters_upper = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
                         'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
english_letters_lower = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
                         't', 'u', 'v', 'w', 'x', 'y', 'z']
global_punctuations = ['!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=',
                       '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~']

arabic_letters = ['ا', 'أ', 'آ', 'إ', 'ء', 'ب', 'ت', 'ث', 'ج', 'ح', 'خ', 'د', 'ذ', 'ر', 'ز', 'س', 'ش', 'ص', 'ض', 'ط',
                  'ظ', 'ع', 'غ', 'ف', 'ق', 'ك', 'ل', 'م', 'ن', 'ه', 'ة', 'و', 'ؤ', 'ي', 'ى', 'ئ']
arabic_numbers = ['٠', '١', '٢', '٣', '٤', '٥', '٦', '٧', '٨', '٩']
arabic_punctuations = ["؛", "÷", "×", "‘", "؟"]
arabic_formatters = ["ً", "ٍ", "ِ", "ُ", "َ", "ٌ", "ْ", "ّ"]


def alphapet(
        is_english_letters_upper: bool = True,
        is_english_letters_lower: bool = True,
        is_global_punctuations: bool = True,
        is_arabic_letters: bool = True,
        is_arabic_numbers: bool = True,
        is_arabic_punctuations: bool = True,
        is_arabic_formatters: bool = True
) -> list:
    all = []
    empty = lambda lst: ['' for i in range(len(lst))]

    # ------------------------------------------------------ #
    if is_english_letters_upper:
        all += english_letters_upper
    else:
        all += empty(english_letters_upper)
    # ------------------------------------------------------ #
    if is_english_letters_lower:
        all += english_letters_lower
    else:
        all += empty(english_letters_lower)
    # ------------------------------------------------------ #
    if is_global_punctuations:
        all += global_punctuations
    else:
        all += empty(global_punctuations)
    # ------------------------------------------------------ #
    if is_arabic_letters:
        all += arabic_letters
    else:
        all += empty(arabic_letters)
    # ------------------------------------------------------ #
    if is_arabic_numbers:
        all += arabic_numbers
    else:
        all += empty(arabic_numbers)
    # ------------------------------------------------------ #
    if is_arabic_punctuations:
        all += arabic_punctuations
    else:
        all += empty(arabic_punctuations)
    # ------------------------------------------------------ #
    if is_arabic_formatters:
        all += arabic_formatters
    else:
        all += empty(arabic_formatters)
    # ------------------------------------------------------ #

    return all


def Encode_dummy(string: str, seperator: str = '.',
                 is_english_letters_upper: bool = True,
                 is_english_letters_lower: bool = True,
                 is_global_punctuations: bool = True,
                 is_arabic_letters: bool = True,
                 is_arabic_numbers: bool = True,
                 is_arabic_punctuations: bool = True,
                 is_arabic_formatters: bool = True
                 ) -> str:
    encoded = []
    a = alphapet(is_english_letters_upper, is_english_letters_lower, is_global_punctuations, is_arabic_letters,
                 is_arabic_numbers, is_arabic_punctuations, is_arabic_formatters)
    for letter in string:
        if letter in a:
            encoded.append(str(a.index(letter) + 1))
        else:
            encoded.append(letter)
    return seperator.join(encoded)


def Decode_dummy(string: str, seperator: str = '.',
                 is_english_letters_upper: bool = True,
                 is_english_letters_lower: bool = True,
                 is_global_punctuations: bool = True,
                 is_arabic_letters: bool = True,
                 is_arabic_numbers: bool = True,
                 is_arabic_punctuations: bool = True,
                 is_arabic_formatters: bool = True
                 ) -> str:
    decoded = ''
    a = alphapet(is_english_letters_upper, is_english_letters_lower, is_global_punctuations, is_arabic_letters,
                 is_arabic_numbers, is_arabic_punctuations, is_arabic_formatters)

    for l in string.split(seperator):
        try:
            decoded += a[int(l) - 1]
        except Exception:
            decoded += l
    return decoded
