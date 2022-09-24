version = "2.1.2"

v1_0_0 = ['base16', 'base32', 'base58', 'base64', 'base85', 'base64.urlsafe', 'morse', 'rot13', 'caesar', 'hexdump', 'dummy', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3.224', 'sha3.256', 'sha3.384', 'sha3.512', 'shake128', 'shake256', 'blake2s', 'blake2b', 'hmac']
"""
V1.0.0:
    add 26 new types
    total 26 type
"""
v2_0_0 = ['binary', 'braille', 'url', 'md2', 'md4', 'adler32', 'ripemd160', 'keccak224', 'keccak256', 'keccak384', 'keccak512', 'crc8', 'crc16', 'crc32', 'ntlm', 'cmac', 'bcrypt', 'poly1305', 'whirlpool', 'aes128', 'punycode']
"""
V2.0.0:
    add 21 new types
    total 47 type
"""


v2_0_1 = []
"""
v2_0_1
Patches:
	(hBase58.py:12):
		Base58 encode even if it put on decode.
	(hSha224.py:6,8):
		Sha224 hash on sha1
"""


v2_1_2 = ["hexadecimal", "color to rgb", "color to hex", "hex to color", "hex to rgb", "rgb to hex", "rgb to color", "html", "kmac128", "kmac256", "timestamp"]
"""
v2_1_2
Added:
    1. added 11 more new types.
    2. searchable types.
    3. added morse code seperators.
    3. added morse code spacers.
    4. added more and implementable morse code, _ and . characters.
Edited:
    1. From (Window starts in full-screen mode) to (normal mode).
    2. implemented morse (code).
Updated:
    Dummy:
        1. can select characters:
            1. english letters upper
            2. english letters lower
            3. global punctuations
            4. arabic letters
            5. arabic numbers
            6. arabic punctuations
            7. arabic formatters
        2. added more characters:
            1. arabic punctuations
            2. arabic formatters
        3. added 5 more seperators:
            1. arabic punctuations
Patches:
    1. morse characters wrong implementation
"""

# V3.0.0 (I just don't know when, BUT I'LL SEE)
#
# Plan to add:
#     ~ vigenere cipher
#     ~ timestamp converter
#     .. and else